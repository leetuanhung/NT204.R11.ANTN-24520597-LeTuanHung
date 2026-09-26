"""Kiểm tra độ ổn định: gói và file PCAP bị làm hỏng ngẫu nhiên không được làm crash.

Chạy:  python -m unittest -v tests.test_robustness
Dùng seed cố định để lần chạy nào cũng cho cùng kết quả.
"""

import contextlib
import io
import logging
import os
import random
import tempfile
import unittest

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Dot1Q, Ether, IPOption_Router_Alert, Raw, wrpcap

from ids.capture import capture_pcap
from ids.detector import detect_app
from ids.parsers.errors import ParseError
from ids.parsers.http import parse_http
from ids.parsers.network import ETHERTYPE_IPV4, parse_ipv4, parse_link
from ids.parsers.transport import parse_tcp, parse_udp
from main import PacketPrinter

ETH = Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
SEEDS = [
    ETH / IP() / TCP(flags="S", options=[("MSS", 1460), ("SAckOK", b""),
                                         ("Timestamp", (1, 2)), ("NOP", None), ("WScale", 7)]),
    ETH / IP() / TCP(flags="PA") / b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
    ETH / Dot1Q(vlan=5) / IP(options=[IPOption_Router_Alert()]) / TCP() / Raw(b"x" * 50),
    ETH / IP() / UDP() / b"abc",
    ETH / IP() / UDP(sport=5000, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")),
    ETH / IP() / TCP(sport=5000, dport=25, flags="PA") / b"EHLO client\r\n",
    ETH / IP() / TCP(sport=80, dport=5000, flags="PA") / b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
]


def mutate(rng: random.Random, data: bytes) -> bytes:
    """Làm hỏng dữ liệu theo một trong bốn cách."""
    d = bytearray(data)
    how = rng.randrange(4)
    if how == 0:                                   # Lật vài byte bất kỳ
        for _ in range(rng.randint(1, 6)):
            d[rng.randrange(len(d))] = rng.randrange(256)
    elif how == 1:                                 # Cắt ngắn
        d = d[:rng.randrange(len(d) + 1)]
    elif how == 2:                                 # Toàn byte rác
        d = bytearray(rng.randbytes(rng.randrange(80)))
    else:                                          # Chèn byte rác vào giữa
        pos = rng.randrange(len(d))
        d[pos:pos] = rng.randbytes(rng.randint(1, 10))
    return bytes(d)


class ParserFuzzTest(unittest.TestCase):
    def test_mutated_packets_only_raise_parse_error(self):
        rng = random.Random(1)
        seeds = [bytes(p) for p in SEEDS]
        for i in range(20000):
            data = mutate(rng, rng.choice(seeds))
            linktype = rng.choice([1, 1, 1, 101, 113, 276, 7])
            try:
                _, ethertype, l3 = parse_link(data, linktype)
                if ethertype == ETHERTYPE_IPV4:
                    ip, l4 = parse_ipv4(l3)
                    if ip["frag_offset"] == 0 and ip["proto"] in (6, 17):
                        if ip["proto"] == 6:
                            hdr, payload = parse_tcp(l4)
                            transport = "TCP"
                        else:
                            hdr, payload = parse_udp(l4)
                            transport = "UDP"
                        app = detect_app(transport, hdr["srcport"], hdr["dstport"], payload)
                        if app.protocol == "HTTP":
                            parse_http(payload)
            except ParseError:
                pass                               # Lỗi có kiểm soát: chấp nhận
            except Exception as exc:               # Mọi lỗi khác là bug
                self.fail(f"Lần {i}: {type(exc).__name__}: {exc} | data={data.hex()}")


class DetectorFuzzTest(unittest.TestCase):
    def test_detector_never_raises(self):
        """Detector nhận payload bất kỳ và không bao giờ được ném lỗi, kể cả ParseError."""
        rng = random.Random(3)
        seeds = [b"GET / HTTP/1.1\r\n\r\n", b"HTTP/1.1 200 OK\r\n", b"EHLO a\r\n",
                 b"220 mx ESMTP\r\n", bytes(SEEDS[4][DNS]),
                 b"\x00\x1d" + bytes(SEEDS[4][DNS])]           # DNS qua TCP
        ports = [25, 53, 80, 5353, 8080, 12345, 40000]
        for i in range(30000):
            payload = mutate(rng, rng.choice(seeds))
            transport = rng.choice(["TCP", "UDP"])
            try:
                detect_app(transport, rng.choice(ports), rng.choice(ports), payload)
            except Exception as exc:
                self.fail(f"Lần {i}: {type(exc).__name__}: {exc} | payload={payload.hex()}")


class HttpFuzzTest(unittest.TestCase):
    def test_http_parser_only_raises_parse_error(self):
        """Payload HTTP bị làm hỏng: parser chỉ được phép ném ParseError."""
        rng = random.Random(4)
        seeds = [
            b"GET /a?b=c HTTP/1.1\r\nHost: x\r\nCookie: s=1\r\n\r\n",
            b"POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
            b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            b"HTTP/1.0 404 Not Found\n\nbody",
        ]
        for i in range(30000):
            payload = mutate(rng, rng.choice(seeds))
            try:
                result = parse_http(payload)
                self.assertIn(result["type"], ("request", "response", "continuation"))
            except ParseError:
                pass
            except Exception as exc:
                self.fail(f"Lần {i}: {type(exc).__name__}: {exc} | payload={payload!r}")


class PcapFuzzTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)
        self.tmp.cleanup()

    def test_corrupted_pcap_files_do_not_crash(self):
        good = os.path.join(self.tmp.name, "good.pcap")
        wrpcap(good, SEEDS * 5)
        with open(good, "rb") as f:
            base = f.read()

        rng = random.Random(2)
        path = os.path.join(self.tmp.name, "bad.pcap")
        for i in range(300):
            data = bytearray(base)
            how = rng.randrange(3)
            if how == 0:                           # Lật byte, kể cả header file
                for _ in range(rng.randint(1, 20)):
                    data[rng.randrange(len(data))] = rng.randrange(256)
            elif how == 1:                         # Cắt ngắn file
                data = data[:rng.randrange(len(data) + 1)]
            else:                                  # Hỏng header của một gói (độ dài giả)
                pos = rng.randrange(24, len(data))
                data[pos:pos + 4] = rng.randbytes(4)
            with open(path, "wb") as f:
                f.write(data)
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    capture_pcap(path, PacketPrinter())
            except Exception as exc:
                self.fail(f"Lần {i}: {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    unittest.main()
