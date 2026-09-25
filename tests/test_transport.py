"""Unit test cho ids/parsers/transport.py (TCP).

Chạy:  python -m unittest -v tests.test_transport
"""

import struct
import unittest

from scapy.all import IP, TCP

from ids.parsers.errors import ParseError
from ids.parsers.transport import parse_tcp, parse_tcp_options, tcp_packet_kind

CLIENT, SERVER = "10.0.0.1", "10.0.0.2"


def tcp_bytes(payload=b"", **kw):
    """Byte bắt đầu từ header TCP. Tạo kèm IP để Scapy tính checksum thật."""
    pkt = IP(src=CLIENT, dst=SERVER) / TCP(**kw) / payload
    return bytes(pkt)[20:]


class HandshakeTest(unittest.TestCase):
    """Test case bắt buộc: nhận diện SYN, SYN/ACK, ACK."""

    def test_three_way_handshake(self):
        steps = [
            (dict(sport=40000, dport=80, flags="S", seq=1000), "SYN", "S"),
            (dict(sport=80, dport=40000, flags="SA", seq=5000, ack=1001), "SYN/ACK", "SA"),
            (dict(sport=40000, dport=80, flags="A", seq=1001, ack=5001), "ACK", "A"),
        ]
        for kw, kind, flag_str in steps:
            with self.subTest(kind):
                tcp, payload = parse_tcp(tcp_bytes(**kw))
                self.assertEqual(tcp["kind"], kind)
                self.assertEqual(tcp["flags"]["str"], flag_str)
                self.assertEqual(tcp["srcport"], kw["sport"])
                self.assertEqual(tcp["dstport"], kw["dport"])
                self.assertEqual(tcp["seq"], kw["seq"])
                self.assertEqual(tcp["ack"], kw.get("ack", 0))
                self.assertEqual(tcp["len"], 0)
                self.assertEqual(payload, b"")

        syn, _ = parse_tcp(tcp_bytes(flags="S"))
        self.assertTrue(syn["flags"]["syn"])
        self.assertFalse(syn["flags"]["ack"])
        synack, _ = parse_tcp(tcp_bytes(flags="SA"))
        self.assertTrue(synack["flags"]["syn"] and synack["flags"]["ack"])


class TcpFieldsTest(unittest.TestCase):
    def test_all_fields_match_scapy(self):
        raw = tcp_bytes(b"hello", sport=1234, dport=8080, seq=0xDEADBEEF, ack=42,
                        flags="PA", window=29200, urgptr=0)
        ref = TCP(raw)
        tcp, payload = parse_tcp(raw)
        self.assertEqual(tcp["srcport"], 1234)
        self.assertEqual(tcp["dstport"], 8080)
        self.assertEqual(tcp["seq"], 0xDEADBEEF)
        self.assertEqual(tcp["ack"], 42)
        self.assertEqual(tcp["hdr_len"], 20)
        self.assertEqual(tcp["window_size_value"], 29200)
        self.assertEqual(tcp["checksum"], ref.chksum)
        self.assertEqual(tcp["urgent_pointer"], 0)
        self.assertEqual(tcp["flags"]["value"], int(ref.flags))
        self.assertEqual(tcp["flags"]["str"], str(ref.flags))

    def test_data_packet_with_payload(self):
        """Test case bắt buộc: parse TCP packet có payload."""
        data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        tcp, payload = parse_tcp(tcp_bytes(data, flags="PA"))
        self.assertEqual(tcp["kind"], "PSH/ACK")
        self.assertEqual(tcp["len"], len(data))
        self.assertEqual(payload, data)
        self.assertEqual(bytes.fromhex(tcp["payload"]), data)
        self.assertFalse(tcp["payload_truncated"])

    def test_large_payload_hex_is_capped(self):
        data = b"X" * 3000
        tcp, payload = parse_tcp(tcp_bytes(data, flags="A"))
        self.assertEqual(tcp["len"], 3000)
        self.assertEqual(payload, data)                  # Payload trả về vẫn đầy đủ
        self.assertEqual(len(tcp["payload"]), 1024 * 2)   # Chỉ phần hex bị cắt
        self.assertTrue(tcp["payload_truncated"])

    def test_every_flag(self):
        for letter, name in [("F", "fin"), ("S", "syn"), ("R", "reset"), ("P", "push"),
                             ("A", "ack"), ("U", "urg"), ("E", "ece"), ("C", "cwr"), ("N", "ae")]:
            with self.subTest(name):
                tcp, _ = parse_tcp(tcp_bytes(flags=letter))
                self.assertTrue(tcp["flags"][name])
                self.assertEqual(sum(tcp["flags"][k] for k in
                                     ("fin", "syn", "reset", "push", "ack",
                                      "urg", "ece", "cwr", "ae")), 1)

    def test_kind_labels(self):
        cases = {"FA": "FIN/ACK", "R": "RST", "RA": "RST/ACK", "": "NULL",
                 "FPU": "FIN/PSH/URG"}   # FIN/PSH/URG là Xmas scan
        for flags, label in cases.items():
            with self.subTest(flags=flags):
                tcp, _ = parse_tcp(tcp_bytes(flags=flags))
                self.assertEqual(tcp["kind"], label)

    def test_kind_from_dict(self):
        self.assertEqual(tcp_packet_kind({"syn": True, "ack": True}), "SYN/ACK")
        self.assertEqual(tcp_packet_kind({}), "NULL")


class TcpOptionsTest(unittest.TestCase):
    def test_syn_options(self):
        raw = tcp_bytes(flags="S", options=[("MSS", 1460), ("SAckOK", b""),
                                            ("Timestamp", (123456, 0)), ("NOP", None),
                                            ("WScale", 7)])
        tcp, _ = parse_tcp(raw)
        opts = tcp["options"]
        self.assertEqual(tcp["hdr_len"], 40)
        self.assertEqual(opts["mss_val"], 1460)
        self.assertTrue(opts["sack_perm"])
        self.assertEqual(opts["timestamp_tsval"], 123456)
        self.assertEqual(opts["timestamp_tsecr"], 0)
        self.assertEqual(opts["wscale_shift"], 7)
        self.assertEqual(opts["wscale_multiplier"], 128)
        self.assertEqual(opts["kinds"], [2, 4, 8, 1, 3])
        self.assertNotIn("malformed", opts)

    def test_sack_blocks(self):
        tcp, _ = parse_tcp(tcp_bytes(flags="A", options=[("NOP", None), ("NOP", None),
                                                         ("SAck", (100, 200, 300, 400))]))
        self.assertEqual(tcp["options"]["sack"], [[100, 200], [300, 400]])

    def test_no_options(self):
        tcp, _ = parse_tcp(tcp_bytes(flags="S"))
        self.assertEqual(tcp["options"], {"kinds": []})

    def test_eol_stops_parsing(self):
        opts = parse_tcp_options(bytes([0, 2, 4, 5, 0xB4]))
        self.assertEqual(opts["kinds"], [0])
        self.assertNotIn("mss_val", opts)

    def test_malformed_options_do_not_break_packet(self):
        cases = {
            "length 0": bytes([2, 0, 0, 0]),
            "length 1": bytes([2, 1, 0, 0]),
            "vượt biên": bytes([2, 8, 5, 0xB4]),
            "thiếu byte length": bytes([1, 1, 1, 2]),
        }
        for name, opt in cases.items():
            with self.subTest(name):
                header = struct.pack("!HHIIHHHH", 1, 2, 0, 0, (6 << 12) | 0x002, 0, 0, 0)
                tcp, _ = parse_tcp(header + opt)
                self.assertTrue(tcp["options"]["malformed"])
                self.assertEqual(tcp["kind"], "SYN")   # Phần header chính vẫn đọc đúng


class TcpErrorTest(unittest.TestCase):
    def test_errors(self):
        good = tcp_bytes(flags="S")
        cases = {
            "rỗng": b"",
            "quá ngắn": good[:12],
            "data offset 3": good[:12] + bytes([0x30]) + good[13:],
            "header dài hơn dữ liệu": good[:12] + bytes([0xF0]) + good[13:],  # 60 byte
        }
        for name, data in cases.items():
            with self.subTest(name):
                with self.assertRaises(ParseError) as ctx:
                    parse_tcp(data)
                self.assertIn("TCP", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
