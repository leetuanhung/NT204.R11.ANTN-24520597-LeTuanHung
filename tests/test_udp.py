"""Unit test cho parse_udp trong ids/parsers/transport.py.

Chạy:  python -m unittest -v tests.test_udp
"""

import struct
import unittest

from scapy.all import DNS, DNSQR, IP, UDP

from ids.parsers.errors import ParseError
from ids.parsers.transport import parse_udp


def udp_bytes(payload=b"", **kw):
    """Byte bắt đầu từ header UDP. Tạo kèm IP để Scapy tính length và checksum thật."""
    pkt = IP(src="192.168.1.10", dst="8.8.8.8") / UDP(**kw) / payload
    return bytes(pkt)[20:]


class UdpFieldsTest(unittest.TestCase):
    def test_all_fields_match_scapy(self):
        raw = udp_bytes(b"hello udp", sport=40000, dport=9999)
        ref = UDP(raw)
        udp, payload = parse_udp(raw)
        self.assertEqual(udp["srcport"], 40000)
        self.assertEqual(udp["dstport"], 9999)
        self.assertEqual(udp["length"], ref.len)
        self.assertEqual(udp["length"], 8 + 9)
        self.assertEqual(udp["checksum"], ref.chksum)
        self.assertFalse(udp["checksum_zero"])
        self.assertFalse(udp["truncated"])
        self.assertEqual(udp["len"], 9)
        self.assertEqual(payload, b"hello udp")

    def test_dns_query_payload(self):
        """Test case bắt buộc "UDP": parse gói UDP có payload (một truy vấn DNS)."""
        dns = bytes(DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com", qtype="A")))
        udp, payload = parse_udp(udp_bytes(dns, sport=53000, dport=53))
        self.assertEqual(udp["dstport"], 53)
        self.assertEqual(udp["len"], len(dns))
        self.assertEqual(payload, dns)
        self.assertEqual(bytes.fromhex(udp["payload"]), dns)
        self.assertIn(b"\x07example\x03com\x00", payload)

    def test_empty_payload(self):
        udp, payload = parse_udp(udp_bytes(sport=1, dport=2))
        self.assertEqual(udp["length"], 8)
        self.assertEqual(udp["len"], 0)
        self.assertEqual(udp["payload"], "")
        self.assertEqual(payload, b"")

    def test_zero_checksum(self):
        udp, _ = parse_udp(udp_bytes(b"x", chksum=0))
        self.assertEqual(udp["checksum"], 0)
        self.assertTrue(udp["checksum_zero"])

    def test_large_payload_hex_is_capped(self):
        udp, payload = parse_udp(udp_bytes(b"Y" * 2000))
        self.assertEqual(udp["len"], 2000)
        self.assertEqual(len(payload), 2000)
        self.assertEqual(len(udp["payload"]), 1024 * 2)
        self.assertTrue(udp["payload_truncated"])

    def test_length_bigger_than_data_is_truncated(self):
        raw = udp_bytes(b"A" * 50)
        udp, payload = parse_udp(raw[:30])          # Mất 28 byte cuối
        self.assertTrue(udp["truncated"])
        self.assertEqual(udp["length"], 58)
        self.assertEqual(payload, b"A" * 22)

    def test_length_smaller_than_data_drops_extra_bytes(self):
        header = struct.pack("!HHHH", 1000, 2000, 8 + 4, 0)
        udp, payload = parse_udp(header + b"DATA" + b"\x00" * 10)
        self.assertEqual(payload, b"DATA")
        self.assertEqual(udp["len"], 4)
        self.assertFalse(udp["truncated"])


class UdpErrorTest(unittest.TestCase):
    def test_errors(self):
        cases = {
            "rỗng": b"",
            "7 byte": b"\x00" * 7,
            "length 4": struct.pack("!HHHH", 1, 2, 4, 0),
            "length 0": struct.pack("!HHHH", 1, 2, 0, 0) + b"abc",
        }
        for name, data in cases.items():
            with self.subTest(name):
                with self.assertRaises(ParseError) as ctx:
                    parse_udp(data)
                self.assertIn("UDP", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
