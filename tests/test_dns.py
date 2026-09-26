"""Unit test cho ids/parsers/dns.py.

Chạy:  python -m unittest -v tests.test_dns
Scapy không tự nén tên miền, nên các gói trả lời được gọi .compress() để giống máy chủ DNS thật.
Các gói hỏng được ghép tay từng byte.
"""

import struct
import unittest

from scapy.all import DNS, DNSQR, DNSRR, DNSRRMX, DNSRROPT, DNSRRSOA, DNSRRSRV

from ids.parsers.dns import parse_dns, read_name
from ids.parsers.errors import ParseError


def header(ident=1, flags=0, qd=0, an=0, ns=0, ar=0) -> bytes:
    return struct.pack("!HHHHHH", ident, flags, qd, an, ns, ar)


def name(*labels: bytes) -> bytes:
    return b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"


QUERY = bytes(DNS(id=0xBEEF, rd=1, qd=DNSQR(qname="www.example.com", qtype="A")))

RESPONSE = bytes(DNS(
    id=0xBEEF, qr=1, rd=1, ra=1, qd=DNSQR(qname="www.example.com", qtype="A"),
    an=[DNSRR(rrname="www.example.com", type="CNAME", ttl=300, rdata="example.com"),
        DNSRR(rrname="example.com", type="A", ttl=60, rdata="93.184.216.34")],
).compress())


class RequiredCasesTest(unittest.TestCase):
    """Hai test case bắt buộc của đề liên quan đến DNS."""

    def test_dns_query_domain_and_type(self):
        d = parse_dns(QUERY)
        self.assertEqual(d["id"], 0xBEEF)
        self.assertFalse(d["flags"]["response"])
        self.assertTrue(d["flags"]["recdesired"])
        self.assertEqual(d["flags"]["opcode_name"], "QUERY")
        self.assertEqual(d["count"], {"queries": 1, "answers": 0, "auth_rr": 0, "add_rr": 0})
        self.assertEqual(d["qry"], [{"name": "www.example.com", "type": 1, "type_name": "A",
                                     "class": 1, "class_name": "IN"}])
        self.assertEqual(d["resp"], [])
        self.assertFalse(d["malformed"])

    def test_dns_response_answers(self):
        d = parse_dns(RESPONSE)
        self.assertIn(b"\xc0", RESPONSE)                 # Gói mẫu đúng là có nén tên
        self.assertTrue(d["flags"]["response"])
        self.assertTrue(d["flags"]["recavail"])
        self.assertEqual(d["flags"]["rcode_name"], "NOERROR")
        self.assertEqual(d["count"]["answers"], 2)
        cname, a = d["resp"]
        self.assertEqual((cname["section"], cname["name"], cname["type_name"], cname["ttl"]),
                         ("answer", "www.example.com", "CNAME", 300))
        self.assertEqual(cname["cname"], "example.com")
        self.assertEqual((a["name"], a["type_name"], a["ttl"], a["len"]), ("example.com", "A", 60, 4))
        self.assertEqual(a["a"], "93.184.216.34")
        self.assertFalse(d["malformed"])
        self.assertNotIn("trailing_bytes", d)

    def test_other_query_types(self):
        # Truyền số kiểu vì Scapy gọi kiểu 255 là "ALL", còn Wireshark gọi là "ANY"
        for type_id, type_name in [(28, "AAAA"), (15, "MX"), (16, "TXT"), (255, "ANY")]:
            with self.subTest(type_name):
                d = parse_dns(bytes(DNS(qd=DNSQR(qname="example.com", qtype=type_id))))
                self.assertEqual(d["qry"][0]["type"], type_id)
                self.assertEqual(d["qry"][0]["type_name"], type_name)


class RecordTypesTest(unittest.TestCase):
    def parse_answer(self, rr) -> dict:
        d = parse_dns(bytes(DNS(qr=1, qd=None, an=[rr]).compress()))
        self.assertFalse(d["malformed"], d.get("error"))
        return d["resp"][0]

    def test_aaaa(self):
        rr = self.parse_answer(DNSRR(rrname="example.com", type="AAAA", rdata="2001:db8::1"))
        self.assertEqual(rr["aaaa"], "2001:db8::1")

    def test_ns_ptr(self):
        rr = self.parse_answer(DNSRR(rrname="example.com", type="NS", rdata="ns1.example.com"))
        self.assertEqual(rr["ns"], "ns1.example.com")
        rr = self.parse_answer(DNSRR(rrname="34.216.184.93.in-addr.arpa", type="PTR",
                                     rdata="host.example.com"))
        self.assertEqual(rr["ptr"], "host.example.com")

    def test_mx(self):
        rr = self.parse_answer(DNSRRMX(rrname="example.com", preference=10, exchange="mail.example.com"))
        self.assertEqual(rr["mx"], {"preference": 10, "mail_exchange": "mail.example.com"})

    def test_txt_multiple_strings(self):
        rr = self.parse_answer(DNSRR(rrname="example.com", type="TXT", rdata=["v=spf1 -all", "hello"]))
        self.assertEqual(rr["txt"], ["v=spf1 -all", "hello"])

    def test_srv(self):
        rr = self.parse_answer(DNSRRSRV(rrname="_sip._tcp.example.com", priority=1, weight=5,
                                        port=5060, target="sip.example.com"))
        self.assertEqual(rr["srv"], {"priority": 1, "weight": 5, "port": 5060,
                                     "target": "sip.example.com"})

    def test_nxdomain_with_soa_in_authority(self):
        soa = DNSRRSOA(rrname="example.com", mname="ns1.example.com", rname="admin.example.com",
                       serial=2026092601, refresh=7200, retry=3600, expire=1209600, minimum=300)
        d = parse_dns(bytes(DNS(qr=1, rcode=3, qd=DNSQR(qname="nope.example.com"), ns=[soa]).compress()))
        self.assertEqual(d["flags"]["rcode_name"], "NXDOMAIN")
        rr = d["resp"][0]
        self.assertEqual(rr["section"], "authority")
        self.assertEqual(rr["soa"], {"mname": "ns1.example.com", "rname": "admin.example.com",
                                     "serial_number": 2026092601, "refresh_interval": 7200,
                                     "retry_interval": 3600, "expire_limit": 1209600,
                                     "minimum_ttl": 300})

    def test_opt_edns(self):
        d = parse_dns(bytes(DNS(qd=DNSQR(qname="example.com"), ar=[DNSRROPT(rclass=1232)])))
        opt = d["resp"][0]
        self.assertEqual((opt["section"], opt["type_name"], opt["name"]), ("additional", "OPT", "<Root>"))
        self.assertEqual(opt["opt"]["udp_payload_size"], 1232)
        self.assertTrue(opt["opt"]["do"])              # Scapy mặc định bật cờ DO

    def test_unknown_type_kept_as_hex(self):
        msg = header(qd=0, an=1, flags=0x8000) + name(b"x") + struct.pack("!HHIH", 99, 1, 5, 3) + b"\x01\x02\x03"
        rr = parse_dns(msg)["resp"][0]
        self.assertEqual(rr["type_name"], "TYPE99")
        self.assertEqual(rr["data"], "010203")

    def test_all_sections(self):
        msg = bytes(DNS(qr=1, qd=DNSQR(qname="a.com"),
                        an=[DNSRR(rrname="a.com", rdata="1.1.1.1")],
                        ns=[DNSRR(rrname="a.com", type="NS", rdata="ns.a.com")],
                        ar=[DNSRR(rrname="ns.a.com", rdata="2.2.2.2")]).compress())
        d = parse_dns(msg)
        self.assertEqual([r["section"] for r in d["resp"]], ["answer", "authority", "additional"])


class NameTest(unittest.TestCase):
    def test_compression_pointer(self):
        # "example.com" ở vị trí 12, sau đó "www" + con trỏ về vị trí 12
        msg = header() + name(b"example", b"com") + b"\x03www\xc0\x0c"
        self.assertEqual(read_name(msg, 12), ("example.com", 25))
        self.assertEqual(read_name(msg, 25), ("www.example.com", 31))   # Kết thúc ngay sau con trỏ

    def test_root_name(self):
        self.assertEqual(read_name(header() + b"\x00", 12), ("<Root>", 13))

    def test_special_bytes_escaped(self):
        msg = header(qd=1) + name(b"a.b", b"\x00x", b"back\\slash") + b"\x00\x01\x00\x01"
        self.assertEqual(parse_dns(msg)["qry"][0]["name"], "a\\.b.\\000x.back\\\\slash")

    def test_mdns_flags(self):
        q = parse_dns(bytes(DNS(qd=DNSQR(qname="_http._tcp.local", qtype="PTR", unicastresponse=1))))
        self.assertTrue(q["qry"][0]["unicast_response"])
        self.assertEqual(q["qry"][0]["class"], 1)
        # Scapy 2.7 tách cờ cache-flush thành trường cacheflush riêng
        a = parse_dns(bytes(DNS(qr=1, aa=1, qd=None,
                                an=[DNSRR(rrname="host.local", cacheflush=1, rdata="192.168.1.5")])))
        self.assertTrue(a["resp"][0]["cache_flush"])
        self.assertEqual(a["resp"][0]["class_name"], "IN")


class TcpTest(unittest.TestCase):
    def test_dns_over_tcp(self):
        d = parse_dns(struct.pack("!H", len(RESPONSE)) + RESPONSE, "TCP")
        self.assertEqual(d["tcp_length"], len(RESPONSE))
        self.assertFalse(d["message_truncated"])
        self.assertEqual(d["resp"][1]["a"], "93.184.216.34")

    def test_dns_over_tcp_split_segment(self):
        d = parse_dns(struct.pack("!H", len(RESPONSE)) + RESPONSE[:40], "TCP")
        self.assertTrue(d["message_truncated"])
        self.assertEqual(d["qry"][0]["name"], "www.example.com")   # Phần đầu vẫn đọc được
        self.assertTrue(d["malformed"])


class MalformedTest(unittest.TestCase):
    def test_header_errors(self):
        for data, transport in [(b"", "UDP"), (b"\x00" * 11, "UDP"), (b"\x00", "TCP"),
                                (struct.pack("!H", 5) + b"\x00" * 5, "TCP")]:
            with self.subTest(data=data, transport=transport):
                with self.assertRaises(ParseError):
                    parse_dns(data, transport)

    def assert_malformed(self, msg: bytes, text: str) -> dict:
        d = parse_dns(msg)
        self.assertTrue(d["malformed"])
        self.assertIn(text, d["error"])
        return d

    def test_pointer_loop(self):
        self.assert_malformed(header(qd=1) + b"\xc0\x0c" + b"\x00\x01\x00\x01", "vòng lặp")

    def test_pointer_loop_between_two_names(self):
        # Vị trí 12 trỏ tới 14, vị trí 14 trỏ về 12
        self.assert_malformed(header(qd=1) + b"\xc0\x0e\xc0\x0c", "vòng lặp")

    def test_pointer_out_of_packet(self):
        self.assert_malformed(header(qd=1) + b"\xc3\xff" + b"\x00\x01\x00\x01", "ngoài gói")

    def test_bad_label_type(self):
        self.assert_malformed(header(qd=1) + b"\x41" + b"a" * 65 + b"\x00\x00\x01\x00\x01", "Kiểu nhãn")

    def test_name_too_long(self):
        self.assert_malformed(header(qd=1) + name(*[b"a" * 63] * 5) + b"\x00\x01\x00\x01", "255")

    def test_keeps_parsed_parts(self):
        # Câu hỏi đầu hợp lệ, câu hỏi thứ hai bị cắt
        msg = header(qd=2) + name(b"good", b"com") + b"\x00\x01\x00\x01" + b"\x03ba"
        d = self.assert_malformed(msg, "Nhãn")
        self.assertEqual([q["name"] for q in d["qry"]], ["good.com"])

    def test_counts_bigger_than_data(self):
        msg = header(flags=0x8000, an=5) + name(b"a") + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04"
        d = self.assert_malformed(msg, "Tên miền")
        self.assertEqual(len(d["resp"]), 1)

    def test_rdlength_beyond_data(self):
        msg = header(flags=0x8000, an=1) + name(b"a") + struct.pack("!HHIH", 1, 1, 60, 50) + b"\x01\x02"
        self.assert_malformed(msg, "RDATA")

    def test_bad_rdata_does_not_stop_next_record(self):
        bad_a = name(b"a") + struct.pack("!HHIH", 1, 1, 60, 3) + b"\x01\x02\x03"
        good_a = name(b"b") + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x05\x06\x07\x08"
        d = parse_dns(header(flags=0x8000, an=2) + bad_a + good_a)
        self.assertFalse(d["malformed"])
        self.assertIn("độ dài phải là 4", d["resp"][0]["rdata_malformed"])
        self.assertEqual(d["resp"][0]["data"], "010203")
        self.assertEqual(d["resp"][1]["a"], "5.6.7.8")

    def test_rdata_name_overflows_record(self):
        # CNAME khai báo rdlen 2 nhưng tên thật dài 7 byte
        msg = header(flags=0x8000, an=1) + name(b"a") + struct.pack("!HHIH", 5, 1, 60, 2) + name(b"target")
        d = parse_dns(msg)
        self.assertIn("vượt quá", d["resp"][0]["rdata_malformed"])

    def test_txt_string_overflow(self):
        msg = header(flags=0x8000, an=1) + name(b"a") + struct.pack("!HHIH", 16, 1, 60, 3) + b"\x09ab"
        self.assertIn("TXT", parse_dns(msg)["resp"][0]["rdata_malformed"])

    def test_decompression_budget_stops_slow_packet(self):
        # Tấn công làm chậm: hàng nghìn bản ghi cùng trỏ về một tên 127 nhãn
        long_name = b"\x01a" * 127 + b"\x00"
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04"
        msg = header(flags=0x8000, qd=1, an=4000) + long_name + b"\x00\x01\x00\x01" + rr * 4000
        d = self.assert_malformed(msg, "bước giải nén")
        self.assertLess(len(d["resp"]), 4000)
        self.assertEqual(d["qry"][0]["name"].count("."), 126)   # Phần đã đọc vẫn được giữ

    def test_budget_allows_large_legit_response(self):
        name_www = b"\x03www\x07example\x03com\x00"
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04"
        d = parse_dns(header(flags=0x8000, qd=1, an=2000) + name_www + b"\x00\x01\x00\x01" + rr * 2000)
        self.assertFalse(d["malformed"])
        self.assertEqual(len(d["resp"]), 2000)

    def test_trailing_bytes(self):
        d = parse_dns(QUERY + b"junk")
        self.assertFalse(d["malformed"])
        self.assertEqual(d["trailing_bytes"], 4)


if __name__ == "__main__":
    unittest.main()
