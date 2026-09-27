"""Unit test cho ids/pipeline.py (ghép các tầng thành sự kiện chuẩn hóa).

Chạy:  python -m unittest -v tests.test_pipeline
"""

import base64
import json
import logging
import unittest
from unittest import mock

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, IPv6

from ids import pipeline as pipeline_module
from ids.capture import RawPacket
from ids.linktypes import LINKTYPE_ETHERNET, LINKTYPE_RAW
from ids.pipeline import Pipeline

ETH = Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
CLIENT, SERVER = "10.0.0.1", "10.0.0.2"
TS = 1790400000.25

# Các trường luôn có mặt trong mọi event, để Detection Engine không phải kiểm tra tồn tại
TOP_LEVEL_KEYS = {"packet_id", "timestamp", "time", "source", "frame_len", "src_ip", "dst_ip",
                  "src_port", "dst_port", "network", "transport", "app_protocol",
                  "app_detected_by", "malformed", "truncated", "errors"}


def raw(frame, linktype=LINKTYPE_ETHERNET) -> RawPacket:
    return RawPacket(timestamp=TS, data=bytes(frame), linktype=linktype, source="test")


def tcp(payload=b"", sport=40000, dport=80, flags="PA"):
    return ETH / IP(src=CLIENT, dst=SERVER) / TCP(sport=sport, dport=dport, flags=flags) / payload


def udp(payload=b"", sport=50000, dport=53):
    return ETH / IP(src=CLIENT, dst=SERVER) / UDP(sport=sport, dport=dport) / payload


class EventStructureTest(unittest.TestCase):
    def setUp(self):
        self.p = Pipeline()

    def test_common_fields_always_present(self):
        for frame in [tcp(flags="S"), udp(b"x", dport=9999), ETH / ARP(), b"\x00" * 5]:
            with self.subTest(frame=repr(frame)[:40]):
                event = self.p.process(raw(frame))
                self.assertTrue(TOP_LEVEL_KEYS <= event.keys())

    def test_json_serializable(self):
        frames = [tcp(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"), udp(bytes(DNS(qd=DNSQR(qname="a.com")))),
                  tcp(b"EHLO x\r\n", dport=25), ETH / ARP(), b"\xff" * 30]
        for frame in frames:
            event = self.p.process(raw(frame))
            text = json.dumps(event, ensure_ascii=False)
            self.assertEqual(json.loads(text), event)

    def test_packet_id_and_time(self):
        first = self.p.process(raw(tcp(flags="S")))
        second = self.p.process(raw(tcp(flags="A")))
        self.assertEqual((first["packet_id"], second["packet_id"]), (1, 2))
        self.assertEqual(first["timestamp"], TS)
        self.assertEqual(first["time"], "2026-09-26T05:20:00.250000+00:00")
        self.assertEqual(first["source"], "test")
        self.assertEqual(first["frame_len"], len(bytes(tcp(flags="S"))))


class ProtocolTest(unittest.TestCase):
    def setUp(self):
        self.p = Pipeline()

    def test_tcp_handshake_packet(self):
        e = self.p.process(raw(tcp(flags="S")))
        self.assertEqual((e["network"], e["transport"]), ("IPv4", "TCP"))
        self.assertEqual((e["src_ip"], e["dst_ip"], e["src_port"], e["dst_port"]),
                         (CLIENT, SERVER, 40000, 80))
        self.assertEqual(e["tcp"]["kind"], "SYN")
        self.assertIsNone(e["app_protocol"])          # Không có payload thì không có tầng ứng dụng
        self.assertEqual(e["eth"]["src"], "aa:aa:aa:aa:aa:aa")
        self.assertEqual(e["ip"]["ttl"], 64)
        self.assertFalse(e["malformed"])

    def test_http(self):
        e = self.p.process(raw(tcp(b"GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n")))
        self.assertEqual((e["app_protocol"], e["app_detected_by"]), ("HTTP", "payload+port"))
        self.assertEqual(e["http"]["request"]["full_uri"], "http://example.com/x")
        self.assertNotIn("dns", e)

    def test_http_on_non_standard_port(self):
        e = self.p.process(raw(tcp(b"GET / HTTP/1.1\r\n\r\n", dport=12345)))
        self.assertEqual((e["app_protocol"], e["app_detected_by"]), ("HTTP", "payload"))

    def test_dns_over_udp(self):
        e = self.p.process(raw(udp(bytes(DNS(rd=1, qd=DNSQR(qname="example.com", qtype="MX"))))))
        self.assertEqual((e["transport"], e["app_protocol"]), ("UDP", "DNS"))
        self.assertEqual(e["udp"]["dstport"], 53)
        self.assertEqual(e["dns"]["qry"][0]["type_name"], "MX")

    def test_dns_over_tcp(self):
        msg = bytes(DNS(qd=DNSQR(qname="example.com")))
        e = self.p.process(raw(tcp(len(msg).to_bytes(2, "big") + msg, dport=53)))
        self.assertEqual(e["dns"]["tcp_length"], len(msg))

    def test_smtp(self):
        e = self.p.process(raw(tcp(b"MAIL FROM:<a@example.com>\r\n", dport=25)))
        self.assertEqual(e["app_protocol"], "SMTP")
        self.assertEqual(e["smtp"]["mail_from"], "a@example.com")

    def test_tls_is_unknown_app(self):
        e = self.p.process(raw(tcp(bytes.fromhex("160301020001") + b"\x00" * 50, dport=443)))
        self.assertEqual(e["app_protocol"], "UNKNOWN")
        self.assertEqual(e["tcp"]["len"], 56)

    def test_icmp(self):
        e = self.p.process(raw(ETH / IP(src=CLIENT, dst=SERVER) / ICMP()))
        self.assertEqual((e["transport"], e["src_port"]), ("ICMP", None))
        self.assertNotIn("tcp", e)

    def test_raw_ip_linktype(self):
        e = self.p.process(raw(IP(src=CLIENT, dst=SERVER) / UDP(dport=53) / bytes(DNS()), LINKTYPE_RAW))
        self.assertEqual(e["src_ip"], CLIENT)
        self.assertNotIn("eth", e)

    def test_fragment(self):
        e = self.p.process(raw(ETH / IP(src=CLIENT, dst=SERVER, proto=6, frag=100) / (b"x" * 40)))
        self.assertEqual(e["transport"], "FRAGMENT")
        self.assertNotIn("tcp", e)
        self.assertFalse(e["malformed"])


class UnknownTest(unittest.TestCase):
    """Test case bắt buộc "Unknown protocol": không crash, đánh dấu UNKNOWN."""

    def test_non_ipv4_marked_unknown(self):
        p = Pipeline()
        for frame, name in [(ETH / ARP(), "ARP"), (ETH / IPv6() / UDP(), "IPv6"),
                            (Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb", type=0x88CC) / (b"\x00" * 20),
                             "0x88cc")]:
            with self.subTest(name):
                e = p.process(raw(frame))
                self.assertEqual(e["network"], "UNKNOWN")
                self.assertEqual(e["ethertype_name"], name)
                self.assertFalse(e["malformed"])

    def test_skip_unknown_option(self):
        p = Pipeline(skip_unknown=True)
        self.assertIsNone(p.process(raw(ETH / ARP())))
        self.assertIsNone(p.process(raw(tcp(bytes.fromhex("1603010200"), dport=443))))
        self.assertIsNone(p.process(raw(ETH / IP() / ICMP())))
        kept = p.process(raw(tcp(flags="S")))
        self.assertEqual(kept["packet_id"], 4)       # packet_id vẫn tăng, khớp số thứ tự trong PCAP
        self.assertEqual(p.stats["skipped"], 3)

    def test_skip_unknown_keeps_malformed(self):
        p = Pipeline(skip_unknown=True)
        self.assertIsNotNone(p.process(raw(b"\x00" * 5)))


class MalformedTest(unittest.TestCase):
    """Test case bắt buộc "Malformed packet": không crash, giữ phần đã parse được."""

    def setUp(self):
        self.p = Pipeline()

    def test_short_ethernet(self):
        e = self.p.process(raw(b"\x00" * 5))
        self.assertTrue(e["malformed"])
        self.assertIn("Ethernet", e["errors"][0])

    def test_bad_ipv4_keeps_ethernet(self):
        e = self.p.process(raw(bytes(tcp(flags="S"))[:20]))
        self.assertTrue(e["malformed"])
        self.assertIn("IPv4", e["errors"][0])
        self.assertIn("eth", e)
        self.assertNotIn("ip", e)

    def test_bad_tcp_keeps_ip(self):
        frame = bytearray(bytes(tcp(flags="S")))
        frame[14 + 20 + 12] = 0x30                    # data offset = 3
        e = self.p.process(raw(bytes(frame)))
        self.assertTrue(e["malformed"])
        self.assertEqual(e["transport"], "TCP")
        self.assertEqual(e["src_ip"], CLIENT)
        self.assertNotIn("tcp", e)
        self.assertIn("TCP", e["errors"][0])

    def test_bad_udp(self):
        frame = bytearray(bytes(udp(b"abc")))
        frame[14 + 20 + 4:14 + 20 + 6] = b"\x00\x04"  # length = 4
        e = self.p.process(raw(bytes(frame)))
        self.assertIn("UDP", e["errors"][0])

    def test_dns_header_too_short_keeps_udp(self):
        e = self.p.process(raw(udp(b"short")))
        self.assertTrue(e["malformed"])
        self.assertEqual(e["udp"]["len"], 5)
        self.assertEqual(e["app_protocol"], "DNS")
        self.assertNotIn("dns", e)
        self.assertIn("DNS", e["errors"][0])

    def test_dns_body_malformed_keeps_parsed_parts(self):
        loop = b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c\x00\x01\x00\x01"
        e = self.p.process(raw(udp(loop)))
        self.assertTrue(e["malformed"])
        self.assertTrue(e["dns"]["malformed"])
        self.assertIn("vòng lặp", e["errors"][0])

    def test_truncated_flag(self):
        # Port 9999 để payload không bị đưa cho parser DNS
        e = self.p.process(raw(bytes(udp(b"A" * 100, dport=9999))[:-30]))
        self.assertTrue(e["truncated"])
        self.assertFalse(e["malformed"])

    def test_unexpected_exception_is_caught(self):
        logging.disable(logging.CRITICAL)
        try:
            with mock.patch.object(pipeline_module, "detect_app", side_effect=RuntimeError("bug")):
                e = self.p.process(raw(tcp(b"hello")))
        finally:
            logging.disable(logging.NOTSET)
        self.assertTrue(e["malformed"])
        self.assertEqual(e["errors"], ["internal: RuntimeError: bug"])
        self.assertIn("tcp", e)                       # Tầng trước lỗi vẫn được giữ


class CredentialRedactionTest(unittest.TestCase):
    """Mật khẩu không được lọt vào event, kể cả qua payload hex ở tầng transport."""

    def assert_no_secret(self, event: dict, secret: bytes) -> None:
        text = json.dumps(event)
        self.assertNotIn(secret.decode(), text)
        self.assertNotIn(secret.hex(), text)

    def test_smtp_auth_login_line(self):
        blob = base64.b64encode(b"S3cret!pass")
        e = Pipeline().process(raw(tcp(blob + b"\r\n", dport=25)))
        self.assertEqual(e["smtp"]["type"], "auth_data")
        self.assertEqual(e["tcp"]["payload"], "")
        self.assertTrue(e["tcp"]["payload_redacted"])
        self.assertEqual(e["tcp"]["len"], len(blob) + 2)     # Độ dài vẫn giữ để IDS phân tích
        self.assert_no_secret(e, blob)

    def test_smtp_auth_plain(self):
        blob = base64.b64encode(b"\0alice\0S3cret!pass")
        e = Pipeline().process(raw(tcp(b"AUTH PLAIN " + blob + b"\r\n", dport=25)))
        self.assertEqual(e["smtp"]["auth"]["username"], "alice")
        self.assert_no_secret(e, blob)

    def test_http_basic_auth(self):
        blob = base64.b64encode(b"admin:S3cret!pass")
        e = Pipeline().process(raw(tcp(b"GET / HTTP/1.1\r\nAuthorization: Basic " + blob + b"\r\n\r\n")))
        self.assertTrue(e["tcp"]["payload_redacted"])
        self.assert_no_secret(e, blob)

    def test_normal_packets_not_redacted(self):
        e = Pipeline().process(raw(tcp(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")))
        self.assertNotEqual(e["tcp"]["payload"], "")
        self.assertNotIn("payload_redacted", e["tcp"])


class StatsTest(unittest.TestCase):
    def test_counts(self):
        p = Pipeline()
        for frame in [tcp(b"GET / HTTP/1.1\r\n\r\n"), udp(bytes(DNS(qd=DNSQR(qname="a.com")))),
                      tcp(flags="S"), ETH / ARP(), b"\x00"]:
            p.process(raw(frame))
        self.assertEqual(p.stats["total"], 5)
        self.assertEqual(p.stats["malformed"], 1)
        self.assertEqual((p.stats["HTTP"], p.stats["DNS"], p.stats["TCP"]), (1, 1, 1))


class MaxPayloadTest(unittest.TestCase):
    def test_max_payload_passed_to_transport(self):
        e = Pipeline(max_payload=4).process(raw(tcp(b"ABCDEFGH", dport=9999)))
        self.assertEqual(e["tcp"]["payload"], b"ABCD".hex())
        self.assertTrue(e["tcp"]["payload_truncated"])


if __name__ == "__main__":
    unittest.main()
