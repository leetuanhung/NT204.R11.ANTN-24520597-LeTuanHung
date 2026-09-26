"""Unit test cho ids/detector.py (nhận diện giao thức ứng dụng).

Chạy:  python -m unittest -v tests.test_detector
"""

import random
import struct
import unittest

from scapy.all import DNS, DNSQR, DNSRR

from ids.detector import Detection, detect_app, looks_like_dns

HTTP_GET = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
HTTP_POST = (b"POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Length: 17\r\n\r\n"
             b"user=a&pass=12345")
HTTP_RESP = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 2\r\n\r\nhi"

DNS_QUERY = bytes(DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com", qtype="A")))
DNS_RESP = bytes(DNS(id=0x1234, qr=1, rd=1, ra=1, qd=DNSQR(qname="example.com"),
                     an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34")))
# mDNS: bit cao của class là cờ QU (unicast response), ví dụ class 0x8001
MDNS_QUERY = bytes(DNS(qd=DNSQR(qname="_http._tcp.local", qtype="PTR", unicastresponse=1)))
# mDNS trả lời không kèm câu hỏi (qdcount = 0), có bit cache-flush trong class
MDNS_ANSWER = bytes(DNS(qr=1, aa=1, qd=None,
                        an=DNSRR(rrname="host.local", type="A", rclass=0x8001, rdata="192.168.1.5")))


def tcp_dns(msg: bytes) -> bytes:
    """DNS qua TCP có 2 byte độ dài ở đầu."""
    return struct.pack("!H", len(msg)) + msg


class HttpDetectionTest(unittest.TestCase):
    def test_standard_port(self):
        for name, payload, sport, dport in [("GET", HTTP_GET, 40000, 80),
                                            ("POST", HTTP_POST, 40000, 8080),
                                            ("response", HTTP_RESP, 80, 40000)]:
            with self.subTest(name):
                self.assertEqual(detect_app("TCP", sport, dport, payload),
                                 Detection("HTTP", "payload+port"))

    def test_non_standard_port(self):
        """Điểm thưởng mục 5: nhận đúng HTTP trên port không chuẩn."""
        self.assertEqual(detect_app("TCP", 40000, 12345, HTTP_GET), Detection("HTTP", "payload"))
        self.assertEqual(detect_app("TCP", 12345, 40000, HTTP_RESP), Detection("HTTP", "payload"))

    def test_payload_wins_over_port(self):
        # HTTP chạy trên port của DNS vẫn phải ra HTTP
        self.assertEqual(detect_app("TCP", 40000, 53, HTTP_GET), Detection("HTTP", "payload"))

    def test_all_methods(self):
        for method in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"]:
            with self.subTest(method):
                payload = f"{method} / HTTP/1.0\r\n\r\n".encode()
                self.assertEqual(detect_app("TCP", 1, 9999, payload).protocol, "HTTP")

    def test_request_line_only(self):
        # Đoạn TCP chỉ chứa đúng dòng đầu, chưa có xuống dòng
        self.assertEqual(detect_app("TCP", 1, 9999, b"GET / HTTP/1.1").protocol, "HTTP")

    def test_not_http(self):
        cases = {
            "chữ thường": b"get / http/1.1\r\n\r\n",       # Method phân biệt hoa thường (RFC 9110)
            "thiếu version": b"GET /index.html\r\n",
            "method lạ": b"FETCH / HTTP/1.1\r\n",
            "HTTP/2 preface": b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
            "status 999": b"HTTP/1.1 999 Weird\r\n",
            "chữ GET giữa payload": b"xxGET / HTTP/1.1\r\n",
        }
        for name, payload in cases.items():
            with self.subTest(name):
                self.assertEqual(detect_app("TCP", 1, 9999, payload), Detection("UNKNOWN", None))

    def test_http_over_udp_is_not_http(self):
        self.assertEqual(detect_app("UDP", 1, 9999, HTTP_GET), Detection("UNKNOWN", None))


class DnsDetectionTest(unittest.TestCase):
    def test_standard_port(self):
        self.assertEqual(detect_app("UDP", 50000, 53, DNS_QUERY), Detection("DNS", "payload+port"))
        self.assertEqual(detect_app("UDP", 53, 50000, DNS_RESP), Detection("DNS", "payload+port"))

    def test_non_standard_port(self):
        self.assertEqual(detect_app("UDP", 50000, 5300, DNS_QUERY), Detection("DNS", "payload"))

    def test_dns_over_tcp(self):
        self.assertEqual(detect_app("TCP", 50000, 53, tcp_dns(DNS_QUERY)),
                         Detection("DNS", "payload+port"))
        self.assertEqual(detect_app("TCP", 50000, 9953, tcp_dns(DNS_RESP)),
                         Detection("DNS", "payload"))

    def test_mdns(self):
        self.assertEqual(detect_app("UDP", 5353, 5353, MDNS_QUERY), Detection("DNS", "payload+port"))
        self.assertEqual(detect_app("UDP", 5353, 5353, MDNS_ANSWER), Detection("DNS", "payload+port"))

    def test_looks_like_dns_rejects(self):
        good = bytearray(DNS_QUERY)
        long_label = bytearray(good[:12]) + b"\x40" + b"a" * 64 + b"\x00\x00\x01\x00\x01"
        loop_ptr = bytearray(good[:12]) + b"\xc0\x0c\x00\x01\x00\x01"   # Trỏ vào chính nó
        bad_opcode = bytearray(good)
        bad_opcode[2] |= 0x78                                           # opcode = 15
        bad_class = bytearray(good)
        bad_class[-1] = 0x07                                            # class = 7
        too_many = bytearray(good)
        too_many[4:6] = b"\x00\x11"                                     # qdcount = 17
        no_question = bytearray(good)
        no_question[4:6] = b"\x00\x00"                                  # Query không có câu hỏi
        cases = {
            "quá ngắn": bytes(good[:11]),
            "nhãn 64 byte": bytes(long_label),
            "con trỏ vòng lặp": bytes(loop_ptr),
            "opcode sai": bytes(bad_opcode),
            "class sai": bytes(bad_class),
            "qdcount 17": bytes(too_many),
            "query không có câu hỏi": bytes(no_question),
            "tên không kết thúc": bytes(good[:20]),
        }
        for name, msg in cases.items():
            with self.subTest(name):
                self.assertFalse(looks_like_dns(msg))

    def test_malformed_dns_on_port_53_still_labelled_by_port(self):
        # IDS cần thấy gói "giả DNS" trên port 53 (ví dụ DNS tunneling hỏng)
        self.assertEqual(detect_app("UDP", 50000, 53, b"not a dns message at all"),
                         Detection("DNS", "port"))


class SmtpDetectionTest(unittest.TestCase):
    def test_strong_commands_any_port(self):
        for payload in [b"EHLO client.example.com\r\n", b"HELO client\r\n",
                        b"MAIL FROM:<a@example.com>\r\n", b"RCPT TO:<b@example.com>\r\n",
                        b"ehlo lowercase.example\r\n"]:
            with self.subTest(payload=payload):
                self.assertEqual(detect_app("TCP", 40000, 25, payload), Detection("SMTP", "payload+port"))
                self.assertEqual(detect_app("TCP", 40000, 2626, payload), Detection("SMTP", "payload"))

    def test_banner_any_port(self):
        banner = b"220 mail.example.com ESMTP Postfix\r\n"
        self.assertEqual(detect_app("TCP", 9999, 40000, banner), Detection("SMTP", "payload"))

    def test_weak_signals_need_smtp_port(self):
        for payload in [b"250 OK\r\n", b"354 End data with <CR><LF>.<CR><LF>\r\n",
                        b"250-PIPELINING\r\n", b"QUIT\r\n", b"DATA\r\n"]:
            with self.subTest(payload=payload):
                self.assertEqual(detect_app("TCP", 25, 40000, payload), Detection("SMTP", "payload+port"))
                self.assertEqual(detect_app("TCP", 21, 40000, payload), Detection("UNKNOWN", None))

    def test_ftp_and_pop3_not_smtp(self):
        self.assertEqual(detect_app("TCP", 21, 40000, b"220 ProFTPD Server ready\r\n"),
                         Detection("UNKNOWN", None))
        self.assertEqual(detect_app("TCP", 40000, 110, b"QUIT\r\n"), Detection("UNKNOWN", None))

    def test_email_body_on_port_25(self):
        # Sau lệnh DATA, nội dung thư không có chữ ký nào; chỉ port cho biết đây là SMTP
        self.assertEqual(detect_app("TCP", 40000, 25, b"Subject: hi\r\n\r\nHello Bob\r\n"),
                         Detection("SMTP", "port"))


class GeneralDetectionTest(unittest.TestCase):
    def test_empty_payload(self):
        self.assertEqual(detect_app("TCP", 40000, 80, b""), Detection(None, None))

    def test_port_only(self):
        # Đoạn thứ hai của một body HTTP dài: không có dòng đầu, chỉ có port
        self.assertEqual(detect_app("TCP", 40000, 80, b"...tiep noi body..."), Detection("HTTP", "port"))

    def test_tls_is_unknown(self):
        tls = bytes.fromhex("160301020001") + b"\x00" * 100
        self.assertEqual(detect_app("TCP", 40000, 443, tls), Detection("UNKNOWN", None))

    def test_http_port_over_udp_is_not_http(self):
        self.assertEqual(detect_app("UDP", 40000, 80, b"xyz"), Detection("UNKNOWN", None))

    def test_random_payload_no_false_positive(self):
        rng = random.Random(0)
        for _ in range(50000):
            payload = rng.randbytes(rng.randint(1, 300))
            for transport in ("TCP", "UDP"):
                self.assertEqual(detect_app(transport, 40000, 33333, payload).protocol, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
