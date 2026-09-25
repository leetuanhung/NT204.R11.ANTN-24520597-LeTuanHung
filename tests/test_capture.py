"""Unit test cho ids/capture.py.

Chạy:  python -m unittest -v tests.test_capture
Các file PCAP mẫu được tạo tạm thời bằng Scapy, không cần quyền root.
"""

import logging
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scapy.all import IP, TCP, UDP, Ether, wrpcap
from scapy.layers.l2 import CookedLinux

from ids import capture
from ids.capture import (LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_RAW,
                         RawPacket, capture_live, capture_pcap)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def make_packets():
    """Hai packet mẫu: TCP SYN và UDP có payload, có timestamp cố định."""
    p1 = Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb") / \
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S")
    p2 = Ether(src="bb:bb:bb:bb:bb:bb", dst="aa:aa:aa:aa:aa:aa") / \
        IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=53, dport=5353) / b"hello"
    p1.time, p2.time = 1000.5, 1001.25
    return [p1, p2]


class PcapCaptureTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        logging.disable(logging.CRITICAL)   # Ẩn log cảnh báo khi chạy test

    def tearDown(self):
        logging.disable(logging.NOTSET)
        self.tmp.cleanup()

    def path(self, name):
        return os.path.join(self.dir, name)

    def collect(self, path):
        out = []
        capture_pcap(path, out.append)
        return out

    def test_reads_all_packets_in_order(self):
        pkts = make_packets()
        wrpcap(self.path("a.pcap"), pkts)
        got = self.collect(self.path("a.pcap"))

        self.assertEqual(len(got), 2)
        for raw, pkt in zip(got, pkts):
            self.assertIsInstance(raw, RawPacket)
            self.assertEqual(raw.data, bytes(pkt))
            self.assertEqual(raw.linktype, LINKTYPE_ETHERNET)
            self.assertEqual(raw.source, f"pcap:{self.path('a.pcap')}")
        self.assertAlmostEqual(got[0].timestamp, 1000.5, places=5)
        self.assertAlmostEqual(got[1].timestamp, 1001.25, places=5)

    def test_raw_ip_linktype(self):
        wrpcap(self.path("raw.pcap"), [IP(dst="1.1.1.1") / UDP()], linktype=LINKTYPE_RAW)
        got = self.collect(self.path("raw.pcap"))
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].linktype, LINKTYPE_RAW)
        self.assertEqual(got[0].data[0] >> 4, 4)   # Byte đầu là IPv4 header

    def test_pcapng_supported(self):
        from scapy.utils import wrpcapng
        wrpcapng(self.path("a.pcapng"), make_packets())
        self.assertEqual(len(self.collect(self.path("a.pcapng"))), 2)

    def test_truncated_pcap_does_not_crash(self):
        wrpcap(self.path("a.pcap"), make_packets())
        with open(self.path("a.pcap"), "rb") as f:
            data = f.read()
        # Cắt ở nhiều vị trí khác nhau: giữa packet data và giữa record header
        for cut in (10, 20, 30, 40, 60):
            with self.subTest(cut=cut):
                with open(self.path("t.pcap"), "wb") as f:
                    f.write(data[:-cut])
                got = self.collect(self.path("t.pcap"))
                self.assertGreaterEqual(len(got), 1)

    def test_empty_file_does_not_crash(self):
        open(self.path("empty.pcap"), "wb").close()
        self.assertEqual(self.collect(self.path("empty.pcap")), [])

    def test_not_a_pcap_does_not_crash(self):
        with open(self.path("bad.pcap"), "wb") as f:
            f.write(b"day khong phai file pcap" * 10)
        self.assertEqual(self.collect(self.path("bad.pcap")), [])

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            capture_pcap(self.path("khong_ton_tai.pcap"), lambda raw: None)

    def test_handler_error_does_not_stop_reading(self):
        wrpcap(self.path("a.pcap"), make_packets())
        seen = []

        def handler(raw):
            seen.append(raw)
            if len(seen) == 1:
                raise RuntimeError("parser lỗi")

        capture_pcap(self.path("a.pcap"), handler)
        self.assertEqual(len(seen), 2)


class LiveCaptureTest(unittest.TestCase):
    """Giả lập scapy.sniff để test live capture mà không cần root."""

    def setUp(self):
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def run_live(self, packets, handler=None):
        got = []

        def fake_sniff(prn, **kwargs):
            self.sniff_kwargs = kwargs
            for p in packets:
                prn(p)

        with mock.patch.object(capture, "sniff", side_effect=fake_sniff):
            capture_live("eth0", handler or got.append, bpf_filter="tcp", count=5)
        return got

    def test_passes_packets_to_handler(self):
        pkts = make_packets()
        got = self.run_live(pkts)
        self.assertEqual([r.data for r in got], [bytes(p) for p in pkts])
        self.assertTrue(all(r.source == "live:eth0" for r in got))
        self.assertAlmostEqual(got[0].timestamp, 1000.5, places=5)

    def test_sniff_arguments(self):
        self.run_live([])
        self.assertEqual(self.sniff_kwargs["iface"], "eth0")
        self.assertEqual(self.sniff_kwargs["filter"], "tcp")
        self.assertEqual(self.sniff_kwargs["count"], 5)
        self.assertFalse(self.sniff_kwargs["store"])

    def test_linktype_detection(self):
        pkts = [Ether() / IP() / TCP(), CookedLinux() / IP() / TCP(), IP() / UDP()]
        got = self.run_live(pkts)
        self.assertEqual([r.linktype for r in got],
                         [LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_RAW])

    def test_handler_error_does_not_stop_capture(self):
        seen = []

        def handler(raw):
            seen.append(raw)
            raise ValueError("parser lỗi")

        self.run_live(make_packets(), handler)
        self.assertEqual(len(seen), 2)


class MainCliTest(unittest.TestCase):
    """Chạy main.py như người dùng thật để kiểm tra thông báo lỗi."""

    def run_main(self, *args):
        return subprocess.run([sys.executable, "main.py", *args], cwd=ROOT,
                              capture_output=True, text=True, timeout=60)

    def test_missing_pcap_message(self):
        r = self.run_main("--pcap", "khong_ton_tai.pcap")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Không tìm thấy file PCAP", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_invalid_interface_message(self):
        r = self.run_main("--interface", "khong_co_card_nay0", "--count", "1")
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("Traceback", r.stderr)

    def test_requires_mode(self):
        r = self.run_main()
        self.assertEqual(r.returncode, 2)   # argparse báo thiếu tham số


if __name__ == "__main__":
    unittest.main()
