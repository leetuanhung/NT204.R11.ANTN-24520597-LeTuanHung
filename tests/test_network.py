"""Unit test cho ids/parsers/network.py (bỏ header lớp 2 và parse IPv4).

Chạy:  python -m unittest -v tests.test_network
Gói mẫu tạo bằng Scapy rồi lấy bytes(), parser chỉ nhận byte thô.
"""

import unittest

from scapy.all import ARP, IP, TCP, UDP, Dot1AD, Dot1Q, Ether, IPOption_Router_Alert
from scapy.layers.l2 import CookedLinux, CookedLinuxV2

from ids.linktypes import (LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL,
                           LINKTYPE_LINUX_SLL2, LINKTYPE_RAW)
from ids.parsers.errors import ParseError
from ids.parsers.network import (ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6,
                                 ETHERTYPE_NAMES, ipv4_checksum, parse_ipv4, parse_link)

SRC_MAC, DST_MAC = "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"


def eth():
    # Ghi rõ MAC để Scapy không phải tra ARP (tránh cảnh báo khi chạy test)
    return Ether(src=SRC_MAC, dst=DST_MAC)


def ip_bytes(**kw):
    """Byte của một gói IPv4/TCP, bắt đầu từ header IP."""
    return bytes(IP(src="192.168.1.10", dst="8.8.8.8", **kw) / TCP(sport=40000, dport=80))


class ParseLinkTest(unittest.TestCase):
    def test_ethernet(self):
        frame = bytes(eth() / IP() / TCP())
        e, ethertype, l3 = parse_link(frame, LINKTYPE_ETHERNET)
        self.assertEqual(e, {"dst": DST_MAC, "src": SRC_MAC, "type": ETHERTYPE_IPV4})
        self.assertEqual(ethertype, ETHERTYPE_IPV4)
        self.assertEqual(l3, frame[14:])

    def test_vlan_802_1q(self):
        frame = bytes(eth() / Dot1Q(vlan=100) / IP() / TCP())
        e, ethertype, l3 = parse_link(frame, LINKTYPE_ETHERNET)
        self.assertEqual(ethertype, ETHERTYPE_IPV4)
        self.assertEqual(e["vlan"], [100])
        self.assertEqual(e["type"], ETHERTYPE_IPV4)
        self.assertEqual(l3, frame[18:])

    def test_qinq_two_tags(self):
        frame = bytes(eth() / Dot1AD(vlan=200) / Dot1Q(vlan=100) / IP() / TCP())
        e, ethertype, l3 = parse_link(frame, LINKTYPE_ETHERNET)
        self.assertEqual(e["vlan"], [200, 100])
        self.assertEqual(l3, frame[22:])

    def test_raw_ip(self):
        pkt = ip_bytes()
        e, ethertype, l3 = parse_link(pkt, LINKTYPE_RAW)
        self.assertIsNone(e)
        self.assertEqual(ethertype, ETHERTYPE_IPV4)
        self.assertEqual(l3, pkt)

    def test_raw_ipv6_detected_by_version(self):
        _, ethertype, _ = parse_link(b"\x60" + b"\x00" * 39, LINKTYPE_RAW)
        self.assertEqual(ethertype, ETHERTYPE_IPV6)

    def test_linux_sll(self):
        frame = bytes(CookedLinux() / IP() / TCP())
        _, ethertype, l3 = parse_link(frame, LINKTYPE_LINUX_SLL)
        self.assertEqual(ethertype, ETHERTYPE_IPV4)
        self.assertEqual(l3, frame[16:])

    def test_linux_sll2(self):
        frame = bytes(CookedLinuxV2() / IP() / TCP())
        _, ethertype, l3 = parse_link(frame, LINKTYPE_LINUX_SLL2)
        self.assertEqual(ethertype, ETHERTYPE_IPV4)
        self.assertEqual(l3, frame[20:])

    def test_arp_is_not_ipv4(self):
        frame = bytes(eth() / ARP())
        _, ethertype, _ = parse_link(frame, LINKTYPE_ETHERNET)
        self.assertEqual(ethertype, ETHERTYPE_ARP)
        self.assertEqual(ETHERTYPE_NAMES[ethertype], "ARP")

    def test_errors(self):
        cases = {
            "ethernet quá ngắn": (b"\x00" * 10, LINKTYPE_ETHERNET),
            "VLAN bị cắt": (bytes(eth())[:12] + b"\x81\x00\x00", LINKTYPE_ETHERNET),
            "raw rỗng": (b"", LINKTYPE_RAW),
            "SLL quá ngắn": (b"\x00" * 15, LINKTYPE_LINUX_SLL),
            "SLL2 quá ngắn": (b"\x00" * 19, LINKTYPE_LINUX_SLL2),
            "linktype lạ": (b"\x00" * 40, 9999),
        }
        for name, (data, lt) in cases.items():
            with self.subTest(name):
                with self.assertRaises(ParseError):
                    parse_link(data, lt)


class ParseIPv4Test(unittest.TestCase):
    def test_all_fields_match_scapy(self):
        raw = ip_bytes(tos=0xB8, id=4321, ttl=57, flags="DF")
        ref = IP(raw)                     # Scapy parse lại để lấy giá trị chuẩn
        ip, payload = parse_ipv4(raw)

        self.assertEqual(ip["version"], 4)
        self.assertEqual(ip["hdr_len"], 20)
        self.assertEqual(ip["dsfield"], 0xB8)
        self.assertEqual(ip["dsfield_dscp"], 46)   # EF (Expedited Forwarding)
        self.assertEqual(ip["dsfield_ecn"], 0)
        self.assertEqual(ip["len"], ref.len)
        self.assertEqual(ip["id"], 4321)
        self.assertEqual(ip["flags"], {"rb": False, "df": True, "mf": False})
        self.assertEqual(ip["frag_offset"], 0)
        self.assertFalse(ip["is_fragment"])
        self.assertEqual(ip["ttl"], 57)
        self.assertEqual(ip["proto"], 6)
        self.assertEqual(ip["proto_name"], "TCP")
        self.assertEqual(ip["checksum"], ref.chksum)
        self.assertEqual(ip["checksum_status"], "good")
        self.assertEqual(ip["src"], "192.168.1.10")
        self.assertEqual(ip["dst"], "8.8.8.8")
        self.assertEqual(ip["options_len"], 0)
        self.assertFalse(ip["truncated"])
        self.assertEqual(payload, raw[20:])        # Đúng 20 byte TCP header

    def test_proto_names(self):
        for proto, name in [(17, "UDP"), (1, "ICMP"), (250, "UNKNOWN")]:
            with self.subTest(proto=proto):
                ip, _ = parse_ipv4(bytes(IP(proto=proto)))
                self.assertEqual(ip["proto_name"], name)

    def test_fragment(self):
        # frag=185 theo đơn vị 8 byte -> offset 1480 byte
        ip, _ = parse_ipv4(ip_bytes(flags="MF", frag=185))
        self.assertTrue(ip["flags"]["mf"])
        self.assertEqual(ip["frag_offset"], 1480)
        self.assertTrue(ip["is_fragment"])

    def test_first_fragment_has_mf_only(self):
        ip, _ = parse_ipv4(ip_bytes(flags="MF"))
        self.assertEqual(ip["frag_offset"], 0)
        self.assertTrue(ip["is_fragment"])

    def test_reserved_bit(self):
        ip, _ = parse_ipv4(ip_bytes(flags="evil"))   # Scapy gọi bit dự trữ là "evil"
        self.assertTrue(ip["flags"]["rb"])

    def test_bad_checksum(self):
        ip, _ = parse_ipv4(ip_bytes(chksum=0x1234))
        self.assertEqual(ip["checksum"], 0x1234)
        self.assertEqual(ip["checksum_status"], "bad")

    def test_checksum_function(self):
        # Ví dụ kinh điển trong RFC 1071 / Wikipedia: checksum phải là 0xB861
        header = bytes.fromhex("45000073000040004011" "0000" "c0a80001c0a800c7")
        self.assertEqual(ipv4_checksum(header), 0xB861)

    def test_ip_options(self):
        raw = bytes(IP(options=[IPOption_Router_Alert()]) / TCP())
        ip, payload = parse_ipv4(raw)
        self.assertEqual(ip["hdr_len"], 24)
        self.assertEqual(ip["options_len"], 4)
        self.assertEqual(payload, raw[24:])
        self.assertEqual(ip["checksum_status"], "good")

    def test_ethernet_padding_removed(self):
        # Frame Ethernet tối thiểu 60 byte: gói 54 byte được đệm thêm 6 byte 0
        frame = bytes(eth() / IP() / TCP()) + b"\x00" * 6
        _, _, l3 = parse_link(frame, LINKTYPE_ETHERNET)
        ip, payload = parse_ipv4(l3)
        self.assertEqual(len(payload), 20)
        self.assertFalse(ip["truncated"])

    def test_truncated_packet_keeps_what_is_available(self):
        raw = bytes(IP() / UDP() / (b"A" * 100))
        ip, payload = parse_ipv4(raw[:-30])
        self.assertTrue(ip["truncated"])
        self.assertEqual(ip["len"], len(raw))
        self.assertEqual(len(payload), len(raw) - 20 - 30)

    def test_errors(self):
        good = ip_bytes()
        cases = {
            "quá ngắn": good[:12],
            "rỗng": b"",
            "version 6": bytes([0x65]) + good[1:],
            "IHL 3": bytes([0x43]) + good[1:],
            "header dài hơn dữ liệu": bytes([0x4F]) + good[1:40],  # IHL 15 = 60 byte
            "total length nhỏ hơn header": good[:2] + b"\x00\x0a" + good[4:],
        }
        for name, data in cases.items():
            with self.subTest(name):
                with self.assertRaises(ParseError) as ctx:
                    parse_ipv4(data)
                self.assertIn("IPv4", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
