"""Chạy các test case bắt buộc (mục 9 của đề) từ đầu đến cuối.

Mỗi case:
  1. Tạo file PCAP đầu vào bằng Scapy (timestamp cố định, chạy lại cho cùng kết quả).
  2. Chạy main.py THẬT trên file đó, giống người dùng gõ lệnh.
  3. Đọc file JSON Lines mà main.py ghi ra và so với kết quả mong đợi.
  4. Ghi TEST/cases/<nn>_<tên>/: input.pcap, output.jsonl, result.md.

Cách dùng (từ thư mục gốc của dự án):
    python TEST/testcases.py          # chạy tất cả
    python TEST/testcases.py 01 12    # chỉ chạy case 01 và 12
"""

import base64
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Callable

from scapy.all import (ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, IPv6, Raw,
                       RawPcapWriter, conf)

conf.verb = 0
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CASES_DIR = os.path.join("TEST", "cases")
BASE_TIME = 1790400000.0          # 2026-09-26 05:20:00 UTC

CLIENT, SERVER = "192.168.10.5", "93.184.216.34"
DNS_SERVER, MAIL_SERVER = "8.8.8.8", "192.168.10.25"
ETH = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


# ----------------------------------------------------------------- khung chạy
@dataclass
class Check:
    description: str
    expected: Any
    actual: Callable[[list], Any]     # Nhận danh sách event, trả về giá trị thực tế


@dataclass
class Case:
    number: str
    slug: str
    title: str
    requirement: str
    build: Callable[[], list]
    checks: list[Check]
    extra_args: list[str] = field(default_factory=list)
    cut_file_bytes: int = 0           # Cắt bớt cuối file PCAP để giả lập file bị truncated


def tcp(src, dst, sport, dport, flags="PA", seq=0, ack=0, payload=b""):
    pkt = ETH / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
    return pkt / payload if payload else pkt


def udp(src, dst, sport, dport, payload):
    return ETH / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / payload


def ev(i: int, *path: str) -> Callable[[list], Any]:
    """Lấy events[i][path[0]][path[1]]... ; dùng để viết kiểm tra ngắn gọn."""
    def get(events):
        value = events[i]
        for key in path:
            value = value[key]
        return value
    return get


def run_case(case: Case) -> bool:
    folder = os.path.join(CASES_DIR, f"{case.number}_{case.slug}")
    os.makedirs(os.path.join(ROOT, folder), exist_ok=True)
    pcap = os.path.join(folder, "input.pcap")
    output = os.path.join(folder, "output.jsonl")

    packets = case.build()
    # Ghi byte thô với linktype Ethernet (1): case 12 có gói chỉ vài byte, không phải khung hợp lệ
    with RawPcapWriter(os.path.join(ROOT, pcap), linktype=1) as writer:
        writer.write_header(None)                       # Header 24 byte của file PCAP
        for i, pkt in enumerate(packets):
            t = BASE_TIME + i * 0.001                   # Timestamp cố định: chạy lại cho cùng kết quả
            writer.write_packet(bytes(pkt), sec=int(t), usec=round((t % 1) * 1_000_000))
    if case.cut_file_bytes:
        path = os.path.join(ROOT, pcap)
        with open(path, "rb") as f:
            data = f.read()
        with open(path, "wb") as f:
            f.write(data[:-case.cut_file_bytes])

    command = ["python", "main.py", "--pcap", pcap, "--output", output, *case.extra_args]
    proc = subprocess.run([sys.executable, *command[1:]], cwd=ROOT,
                          capture_output=True, text=True, timeout=120)
    with open(os.path.join(ROOT, output), encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]

    checks = [
        Check("Chương trình kết thúc bình thường (mã thoát 0)", 0, lambda _: proc.returncode),
        Check("Không có traceback (không crash)", False, lambda _: "Traceback" in proc.stderr),
        *case.checks,
    ]
    rows, passed = [], 0
    for check in checks:
        try:
            actual = check.actual(events)
        except Exception as exc:                      # Thiếu trường cũng tính là không đạt
            actual = f"LỖI: {type(exc).__name__}: {exc}"
        ok = actual == check.expected
        passed += ok
        rows.append(f"| {check.description} | `{check.expected!r}` | `{actual!r}` | "
                    f"{'ĐẠT' if ok else 'KHÔNG ĐẠT'} |")

    status = "ĐẠT" if passed == len(checks) else "KHÔNG ĐẠT"
    lines = [
        f"# Case {case.number}: {case.title}",
        "",
        f"**Yêu cầu của đề:** {case.requirement}",
        "",
        f"**Kết quả: {status}** ({passed}/{len(checks)} kiểm tra đạt)",
        "",
        "## Lệnh chạy",
        "",
        "```bash",
        " ".join(command),
        "```",
        "",
        f"Đầu vào: `input.pcap` ({len(packets)} gói"
        + (f", cắt bớt {case.cut_file_bytes} byte cuối file" if case.cut_file_bytes else "") + "). "
        f"Đầu ra: `output.jsonl` ({len(events)} sự kiện).",
        "",
        "## Kiểm tra",
        "",
        "| Kiểm tra | Mong đợi | Thực tế | Kết quả |",
        "|---|---|---|---|",
        *rows,
        "",
        "## Màn hình",
        "",
        "```",
        (proc.stdout + proc.stderr).rstrip(),
        "```",
        "",
    ]
    with open(os.path.join(ROOT, folder, "result.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Case {case.number} {case.title}: {status} ({passed}/{len(checks)})")
    return status == "ĐẠT"


# ------------------------------------------------------------ các test case
def build_handshake():
    return [
        tcp(CLIENT, SERVER, 51000, 80, "S", seq=1000),
        tcp(SERVER, CLIENT, 80, 51000, "SA", seq=5000, ack=1001),
        tcp(CLIENT, SERVER, 51000, 80, "A", seq=1001, ack=5001),
    ]


def build_tcp_data():
    return [
        tcp(CLIENT, SERVER, 51001, 9000, "PA", seq=2000, ack=7000, payload=b"Hello IDS, this is TCP data"),
        tcp(SERVER, CLIENT, 9000, 51001, "A", seq=7000, ack=2027),
    ]


UDP_MSG = b"<14>Sep 26 12:20:00 host app: udp test message"


def build_udp():
    return [udp(CLIENT, SERVER, 51002, 9999, UDP_MSG)]


def build_http_get():
    return [tcp(CLIENT, SERVER, 51003, 80, payload=(
        b"GET /search?q=ids&lang=vi HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n"
        b"Accept: text/html\r\n"
        b"Cookie: session=abc123\r\n"
        b"\r\n"))]


POST_BODY = b"username=student&comment=hello+world"


def build_http_post():
    return [tcp(CLIENT, SERVER, 51004, 80, payload=(
        b"POST /login HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(POST_BODY)).encode() + b"\r\n"
        b"\r\n" + POST_BODY))]


HTML = b"<h1>Hello</h1>"


def build_http_response():
    return [
        tcp(SERVER, CLIENT, 80, 51005, payload=(
            b"HTTP/1.1 200 OK\r\n"
            b"Server: nginx/1.24.0\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            b"Set-Cookie: sid=xyz; HttpOnly\r\n"
            b"Content-Length: " + str(len(HTML)).encode() + b"\r\n"
            b"\r\n" + HTML)),
        tcp(SERVER, CLIENT, 80, 51006, payload=(
            b"HTTP/1.1 404 Not Found\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n")),
    ]


def build_dns_query():
    return [
        udp(CLIENT, DNS_SERVER, 53001, 53, DNS(id=0x1a2b, rd=1, qd=DNSQR(qname="www.example.com", qtype="A"))),
        udp(CLIENT, DNS_SERVER, 53002, 53, DNS(id=0x1a2c, rd=1, qd=DNSQR(qname="example.com", qtype="MX"))),
    ]


def build_dns_response():
    response = DNS(id=0x1a2b, qr=1, rd=1, ra=1, qd=DNSQR(qname="www.example.com", qtype="A"),
                   an=[DNSRR(rrname="www.example.com", type="CNAME", ttl=300, rdata="example.com"),
                       DNSRR(rrname="example.com", type="A", ttl=60, rdata="93.184.216.34")])
    return [udp(DNS_SERVER, CLIENT, 53, 53001, response.compress())]   # Nén tên như máy chủ thật


def build_smtp_command():
    return [
        tcp(CLIENT, MAIL_SERVER, 51010, 25, payload=b"EHLO client.example.com\r\n"),
        tcp(CLIENT, MAIL_SERVER, 51010, 25, payload=b"MAIL FROM:<alice@example.com> SIZE=1024\r\n"),
        tcp(CLIENT, MAIL_SERVER, 51010, 25, payload=b"RCPT TO:<bob@example.org>\r\n"),
        tcp(CLIENT, MAIL_SERVER, 51010, 25, payload=b"HELO old-client\r\n"),
    ]


def build_smtp_response():
    return [
        tcp(MAIL_SERVER, CLIENT, 25, 51010, payload=b"220 mail.example.com ESMTP Postfix\r\n"),
        tcp(MAIL_SERVER, CLIENT, 25, 51010, payload=(
            b"250-mail.example.com\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250 STARTTLS\r\n")),
        tcp(MAIL_SERVER, CLIENT, 25, 51010, payload=b"250 2.1.0 Ok\r\n"),
        tcp(MAIL_SERVER, CLIENT, 25, 51010, payload=b"550 5.1.1 <nobody@example.org>: User unknown\r\n"),
    ]


def build_unknown():
    return [
        ETH / ARP(psrc=CLIENT, pdst="192.168.10.1"),                          # Không phải IPv4
        ETH / IPv6(src="fe80::1", dst="ff02::1") / UDP(sport=5353, dport=5353) / b"x",
        Ether(src="02:00:00:00:00:01", dst="01:80:c2:00:00:0e", type=0x88CC) / (b"\x02\x07" + b"\x00" * 30),
        ETH / IP(src=CLIENT, dst=SERVER) / ICMP(),                            # Không phải TCP/UDP
        tcp(CLIENT, SERVER, 51020, 443, payload=bytes.fromhex("160301020001") + b"\x00" * 60),  # TLS
        udp(CLIENT, SERVER, 51021, 40000, b"\x13\x37 unknown binary protocol \xff\xfe"),
    ]


def build_malformed():
    good_tcp = bytes(tcp(CLIENT, SERVER, 51030, 80, "S"))
    good_udp = bytes(udp(CLIENT, DNS_SERVER, 51031, 53, bytes(DNS(qd=DNSQR(qname="a.com")))))
    bad_ihl = bytearray(good_tcp)
    bad_ihl[14] = 0x43                                  # IHL = 3 (< 5)
    bad_tcp_off = bytearray(good_tcp)
    bad_tcp_off[14 + 20 + 12] = 0x30                    # TCP data offset = 3 (< 5)
    bad_udp_len = bytearray(good_udp)
    bad_udp_len[14 + 20 + 4:14 + 20 + 6] = b"\x00\x04"  # UDP length = 4 (< 8)
    dns_loop = b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c\x00\x01\x00\x01"
    return [
        Raw(good_tcp[:10]),                                          # 1. Ethernet thiếu byte
        Raw(good_tcp[:26]),                                          # 2. IPv4 thiếu header
        Ether(bytes(bad_ihl)),                                       # 3. IHL sai
        Ether(bytes(bad_tcp_off)),                                   # 4. TCP data offset sai
        Ether(bytes(bad_udp_len)),                                   # 5. UDP length sai
        udp(CLIENT, DNS_SERVER, 51032, 53, dns_loop),                # 6. DNS con trỏ vòng lặp
        udp(CLIENT, DNS_SERVER, 51033, 53, b"short"),                # 7. DNS thiếu header
        tcp(CLIENT, SERVER, 51034, 80, payload=b"GET / HTTP/1.1\r\nHost: \xff\xfe\x80\r\n\r\n"),  # 8. Byte không decode được
        tcp(CLIENT, SERVER, 51035, 80, "S"),                         # 9. Gói cuối, sẽ bị cắt cụt trong file
    ]


def build_http_non_standard():
    return [
        tcp(CLIENT, SERVER, 51040, 4444, payload=b"GET /shell?cmd=id HTTP/1.1\r\nHost: c2.example.net\r\n\r\n"),
        tcp(SERVER, CLIENT, 4444, 51040, payload=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
    ]


CASES = [
    Case("01", "tcp_handshake", "TCP handshake", "Nhận diện SYN, SYN/ACK, ACK", build_handshake, [
        Check("Số sự kiện", 3, len),
        Check("Gói 1: loại gói", "SYN", ev(0, "tcp", "kind")),
        Check("Gói 1: cờ SYN bật, ACK tắt", (True, False),
              lambda e: (e[0]["tcp"]["flags"]["syn"], e[0]["tcp"]["flags"]["ack"])),
        Check("Gói 2: loại gói", "SYN/ACK", ev(1, "tcp", "kind")),
        Check("Gói 2: cờ SYN và ACK cùng bật", (True, True),
              lambda e: (e[1]["tcp"]["flags"]["syn"], e[1]["tcp"]["flags"]["ack"])),
        Check("Gói 2: ack = seq của gói 1 + 1", 1001, ev(1, "tcp", "ack")),
        Check("Gói 3: loại gói", "ACK", ev(2, "tcp", "kind")),
        Check("Gói 3: ack = seq của gói 2 + 1", 5001, ev(2, "tcp", "ack")),
        Check("Chiều gói 1: IP và port", (CLIENT, 51000, SERVER, 80),
              lambda e: (e[0]["src_ip"], e[0]["src_port"], e[0]["dst_ip"], e[0]["dst_port"])),
        Check("Gói bắt tay không có tầng ứng dụng", [None, None, None],
              lambda e: [x["app_protocol"] for x in e]),
    ]),
    Case("02", "tcp_data", "TCP data", "Parse TCP packet có payload", build_tcp_data, [
        Check("Transport", "TCP", ev(0, "transport")),
        Check("Loại gói", "PSH/ACK", ev(0, "tcp", "kind")),
        Check("Độ dài payload", 27, ev(0, "tcp", "len")),
        Check("Payload (giải hex)", "Hello IDS, this is TCP data",
              lambda e: bytes.fromhex(e[0]["tcp"]["payload"]).decode()),
        Check("seq, ack", (2000, 7000), lambda e: (e[0]["tcp"]["seq"], e[0]["tcp"]["ack"])),
        Check("Gói trả lời xác nhận đủ 27 byte (ack = 2000 + 27)", 2027, ev(1, "tcp", "ack")),
        Check("Giao thức ứng dụng (port 9000, dữ liệu lạ)", "UNKNOWN", ev(0, "app_protocol")),
    ]),
    Case("03", "udp", "UDP", "Parse UDP packet", build_udp, [
        Check("Transport", "UDP", ev(0, "transport")),
        Check("Port nguồn, đích", (51002, 9999), lambda e: (e[0]["udp"]["srcport"], e[0]["udp"]["dstport"])),
        Check("Trường length (8 byte header + payload)", 8 + len(UDP_MSG), ev(0, "udp", "length")),
        Check("Độ dài payload", len(UDP_MSG), ev(0, "udp", "len")),
        Check("Payload (giải hex)", UDP_MSG.decode(),
              lambda e: bytes.fromhex(e[0]["udp"]["payload"]).decode()),
        Check("Checksum có giá trị (khác 0)", False, ev(0, "udp", "checksum_zero")),
        Check("Không bị đánh dấu hỏng", False, ev(0, "malformed")),
    ]),
    Case("04", "http_get", "HTTP GET", "Parse HTTP request", build_http_get, [
        Check("Giao thức ứng dụng", ("HTTP", "payload+port"),
              lambda e: (e[0]["app_protocol"], e[0]["app_detected_by"])),
        Check("Method", "GET", ev(0, "http", "request", "method")),
        Check("URI", "/search?q=ids&lang=vi", ev(0, "http", "request", "uri")),
        Check("Version", "HTTP/1.1", ev(0, "http", "request", "version")),
        Check("URL đầy đủ", "http://example.com/search?q=ids&lang=vi", ev(0, "http", "request", "full_uri")),
        Check("Host", "example.com", ev(0, "http", "host")),
        Check("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)", ev(0, "http", "user_agent")),
        Check("Cookie", "session=abc123", ev(0, "http", "cookie")),
        Check("Header đầy đủ", True, ev(0, "http", "header_complete")),
    ]),
    Case("05", "http_post", "HTTP POST", "Parse HTTP request có body", build_http_post, [
        Check("Method", "POST", ev(0, "http", "request", "method")),
        Check("URI", "/login", ev(0, "http", "request", "uri")),
        Check("Content-Type", "application/x-www-form-urlencoded", ev(0, "http", "content_type")),
        Check("Content-Length", len(POST_BODY), ev(0, "http", "content_length")),
        Check("Body", POST_BODY.decode(), ev(0, "http", "file_data")),
        Check("Độ dài body", len(POST_BODY), ev(0, "http", "body_len")),
        Check("Body đầy đủ trong gói", True, ev(0, "http", "body_complete")),
    ]),
    Case("06", "http_response", "HTTP response", "Parse status code và header", build_http_response, [
        Check("Gói 1: status code", 200, ev(0, "http", "response", "code")),
        Check("Gói 1: phrase", "OK", ev(0, "http", "response", "phrase")),
        Check("Gói 1: Server", "nginx/1.24.0", ev(0, "http", "server")),
        Check("Gói 1: Content-Type", "text/html; charset=utf-8", ev(0, "http", "content_type")),
        Check("Gói 1: Set-Cookie", ["sid=xyz; HttpOnly"], ev(0, "http", "set_cookie")),
        Check("Gói 1: số header", 4, lambda e: len(e[0]["http"]["headers"])),
        Check("Gói 1: body", HTML.decode(), ev(0, "http", "file_data")),
        Check("Gói 2: status code và phrase", (404, "Not Found"),
              lambda e: (e[1]["http"]["response"]["code"], e[1]["http"]["response"]["phrase"])),
    ]),
    Case("07", "dns_query", "DNS Query", "Parse domain và query type", build_dns_query, [
        Check("Giao thức ứng dụng", ("DNS", "payload+port"),
              lambda e: (e[0]["app_protocol"], e[0]["app_detected_by"])),
        Check("Gói 1: là câu hỏi (QR = 0)", False, ev(0, "dns", "flags", "response")),
        Check("Gói 1: transaction id", 0x1a2b, ev(0, "dns", "id")),
        Check("Gói 1: domain", "www.example.com", ev(0, "dns", "qry", 0, "name")),
        Check("Gói 1: query type", ("A", 1),
              lambda e: (e[0]["dns"]["qry"][0]["type_name"], e[0]["dns"]["qry"][0]["type"])),
        Check("Gói 1: class", "IN", ev(0, "dns", "qry", 0, "class_name")),
        Check("Gói 2: domain và query type", ("example.com", "MX"),
              lambda e: (e[1]["dns"]["qry"][0]["name"], e[1]["dns"]["qry"][0]["type_name"])),
    ]),
    Case("08", "dns_response", "DNS Response", "Parse ít nhất một answer", build_dns_response, [
        Check("Là câu trả lời (QR = 1)", True, ev(0, "dns", "flags", "response")),
        Check("Mã trả lời", "NOERROR", ev(0, "dns", "flags", "rcode_name")),
        Check("Số answer khai báo", 2, ev(0, "dns", "count", "answers")),
        Check("Số answer đọc được", 2, lambda e: len(e[0]["dns"]["resp"])),
        Check("Answer 1: CNAME", ("www.example.com", "CNAME", "example.com", 300),
              lambda e: tuple(e[0]["dns"]["resp"][0][k] for k in ("name", "type_name", "cname", "ttl"))),
        Check("Answer 2: A", ("example.com", "A", "93.184.216.34", 60),
              lambda e: tuple(e[0]["dns"]["resp"][1][k] for k in ("name", "type_name", "a", "ttl"))),
        Check("Gói có dùng nén tên (con trỏ 0xC0)", True,
              lambda e: "c00c" in e[0]["udp"]["payload"]),
        Check("Không bị đánh dấu hỏng", False, ev(0, "dns", "malformed")),
    ]),
    Case("09", "smtp_command", "SMTP command", "Parse HELO/EHLO, MAIL FROM hoặc RCPT TO",
         build_smtp_command, [
        Check("Giao thức ứng dụng", ["SMTP"] * 4, lambda e: [x["app_protocol"] for x in e]),
        Check("Gói 1: lệnh EHLO", {"command": "EHLO", "parameter": "client.example.com"},
              ev(0, "smtp", "req")),
        Check("Gói 1: tên máy khai báo", "client.example.com", ev(0, "smtp", "helo")),
        Check("Gói 2: lệnh MAIL", "MAIL", ev(1, "smtp", "req", "command")),
        Check("Gói 2: người gửi", "alice@example.com", ev(1, "smtp", "mail_from")),
        Check("Gói 3: lệnh RCPT", "RCPT", ev(2, "smtp", "req", "command")),
        Check("Gói 3: người nhận", ["bob@example.org"], ev(2, "smtp", "rcpt_to")),
        Check("Gói 4: lệnh HELO", {"command": "HELO", "parameter": "old-client"}, ev(3, "smtp", "req")),
    ]),
    Case("10", "smtp_response", "SMTP response", "Parse SMTP status code", build_smtp_response, [
        Check("Status code của 4 gói", [220, 250, 250, 550],
              lambda e: [x["smtp"]["response"]["code"] for x in e]),
        Check("Gói 1: banner", "mail.example.com ESMTP Postfix", ev(0, "smtp", "response", "parameter")),
        Check("Gói 2: phản hồi nhiều dòng", True, ev(1, "smtp", "response", "multiline")),
        Check("Gói 2: tính năng máy chủ", ["PIPELINING", "SIZE 10240000", "STARTTLS"],
              ev(1, "smtp", "response", "extensions")),
        Check("Gói 3: mã trạng thái mở rộng", "2.1.0", ev(2, "smtp", "response", "enhanced_status")),
        Check("Gói 4: mã lỗi và mã mở rộng", (550, "5.1.1"),
              lambda e: (e[3]["smtp"]["response"]["code"], e[3]["smtp"]["response"]["enhanced_status"])),
    ]),
    Case("11", "unknown_protocol", "Unknown protocol", "Không crash", build_unknown, [
        Check("Số sự kiện (không gói nào bị mất)", 6, len),
        Check("ARP, IPv6, LLDP: network là UNKNOWN", ["UNKNOWN"] * 3,
              lambda e: [x["network"] for x in e[:3]]),
        Check("Tên EtherType", ["ARP", "IPv6", "0x88cc"], lambda e: [x["ethertype_name"] for x in e[:3]]),
        Check("ICMP: transport không phải TCP/UDP", "ICMP", ev(3, "transport")),
        Check("TLS port 443 và dữ liệu lạ port 40000: app UNKNOWN", ["UNKNOWN", "UNKNOWN"],
              lambda e: [x["app_protocol"] for x in e[4:6]]),
        Check("Không gói nào bị coi là hỏng", 0, lambda e: sum(x["malformed"] for x in e)),
    ]),
    Case("12", "malformed_packet", "Malformed packet", "Không crash", build_malformed, [
        Check("Số sự kiện (gói cuối bị cắt vẫn được xử lý)", 9, len),
        Check("Gói 1-7 bị đánh dấu malformed", [True] * 7, lambda e: [x["malformed"] for x in e[:7]]),
        Check("Gói 1: lỗi Ethernet", True, lambda e: e[0]["errors"][0].startswith("Ethernet")),
        Check("Gói 2, 3: lỗi IPv4", [True, True], lambda e: [x["errors"][0].startswith("IPv4") for x in e[1:3]]),
        Check("Gói 4: lỗi TCP, vẫn giữ IP nguồn", (True, CLIENT),
              lambda e: (e[3]["errors"][0].startswith("TCP"), e[3]["src_ip"])),
        Check("Gói 5: lỗi UDP", True, lambda e: e[4]["errors"][0].startswith("UDP")),
        Check("Gói 6: DNS vòng lặp con trỏ, giữ nhóm dns", (True, True),
              lambda e: ("vòng lặp" in e[5]["errors"][0], "dns" in e[5])),
        Check("Gói 7: DNS thiếu header, vẫn giữ nhóm udp", (True, True),
              lambda e: (e[6]["errors"][0].startswith("DNS"), "udp" in e[6])),
        Check("Gói 8: byte không decode được, không hỏng, Host đọc được", (False, 3),
              lambda e: (e[7]["malformed"], len(e[7]["http"]["host"]))),
        Check("Gói 9 (bị cắt trong file): vẫn có sự kiện", 9, ev(8, "packet_id")),
    ], cut_file_bytes=10),
    Case("13", "http_non_standard_port", "HTTP trên port không chuẩn (điểm thưởng mục 5)",
         "Nhận diện đúng application protocol trên non-standard port", build_http_non_standard, [
        Check("Gói 1: giao thức và cách nhận diện", ("HTTP", "payload"),
              lambda e: (e[0]["app_protocol"], e[0]["app_detected_by"])),
        Check("Gói 1: port đích", 4444, ev(0, "dst_port")),
        Check("Gói 1: URL đầy đủ", "http://c2.example.net/shell?cmd=id", ev(0, "http", "request", "full_uri")),
        Check("Gói 2: response trên port 4444", ("HTTP", "payload", 200),
              lambda e: (e[1]["app_protocol"], e[1]["app_detected_by"], e[1]["http"]["response"]["code"])),
    ]),
]


def main() -> int:
    wanted = set(sys.argv[1:])
    selected = [c for c in CASES if not wanted or c.number in wanted]
    results = [run_case(c) for c in selected]
    print(f"Tổng: {sum(results)}/{len(results)} case đạt")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
