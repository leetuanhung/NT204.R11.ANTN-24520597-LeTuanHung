"""Chương trình chính: bắt gói (live hoặc PCAP) -> pipeline -> file JSON Lines.

Ví dụ:
    python main.py --pcap test.pcap
    sudo ./venv/bin/python main.py --interface wlp1s0 --count 100
"""

import argparse
import logging
import os
import socket
import sys

from ids.capture import RawPacket, capture_live, capture_pcap
from ids.output import JsonlWriter
from ids.pipeline import Pipeline
from ids.parsers.transport import MAX_PAYLOAD_HEX

DEFAULT_OUTPUT = "output/events.jsonl"


def summarize(event: dict) -> str:
    """Một dòng dễ đọc cho màn hình, tạo từ event (không đọc lại byte thô)."""
    head = f"#{event['packet_id']}"
    if event["network"] == "UNKNOWN" and "ethertype_name" in event:
        return f"{head} {event['ethertype_name']} UNKNOWN"
    if event["src_ip"] is None:
        return f"{head} MALFORMED {'; '.join(event['errors'])}"

    src, dst = event["src_ip"], event["dst_ip"]
    if event["src_port"] is not None:
        src, dst = f"{src}:{event['src_port']}", f"{dst}:{event['dst_port']}"
    text = f"{head} {src} -> {dst} {event['transport']}"
    if "tcp" in event:
        t = event["tcp"]
        text += f" [{t['kind']}] seq={t['seq']} ack={t['ack']} win={t['window_size_value']} len={t['len']}"
    elif "udp" in event:
        text += f" len={event['udp']['len']}"
    elif event["transport"] == "FRAGMENT":
        text += f" offset={event['ip']['frag_offset']}"

    if event["app_protocol"]:
        by = event["app_detected_by"]
        text += f" app={event['app_protocol']}" + (f"({by})" if by else "")
        if "http" in event:
            text += http_summary(event["http"])
        elif "dns" in event:
            text += dns_summary(event["dns"])
        elif "smtp" in event:
            text += smtp_summary(event["smtp"])
    if event["malformed"] and "dns" not in event:
        text += f" MALFORMED {'; '.join(event['errors'])}"
    if event["truncated"]:
        text += " (truncated)"
    return text


def smtp_summary(smtp: dict) -> str:
    """Tóm tắt: " EHLO client", " 250 OK", " auth data (12 bytes)", " message Subject: ..."."""
    if smtp["type"] == "request":
        text = f" {smtp['command_line']}"
        if len(smtp["commands"]) > 1:
            text += f" (+{len(smtp['commands']) - 1} lệnh)"
        return text
    if smtp["type"] == "response":
        res = smtp["response"]
        text = f" {res['code']} {res['parameter']}".rstrip()
        if res["multiline"]:
            text += f" (+{len(res['lines']) - 1} dòng)"
        if len(smtp["responses"]) > 1:
            text += f" (+{len(smtp['responses']) - 1} phản hồi)"
        return text
    if smtp["type"] == "auth_data":
        return f" auth data ({smtp['auth_data']['len']} bytes, đã ẩn)"
    subject = smtp["data"].get("headers", {}).get("subject")
    return f" message Subject: {subject}" if subject else f" message ({smtp['data']['lines']} dòng)"


def dns_summary(dns: dict) -> str:
    """Tóm tắt: " query A example.com" hoặc " response NOERROR A example.com -> 1.2.3.4"."""
    q = dns["qry"][0] if dns["qry"] else None
    question = f" {q['type_name']} {q['name']}" if q else ""
    if not dns["flags"]["response"]:
        text = f" query{question}"
    else:
        answers = []
        for rr in dns["resp"]:
            if rr["section"] != "answer":
                continue
            value = (rr.get("a") or rr.get("aaaa") or rr.get("cname") or rr.get("ns")
                     or rr.get("ptr") or rr.get("mx", {}).get("mail_exchange")
                     or " ".join(rr.get("txt", [])) or rr.get("srv", {}).get("target")
                     or rr.get("type_name"))
            answers.append(value)
        text = f" response {dns['flags']['rcode_name']}{question}"
        if answers:
            text += " -> " + ", ".join(answers[:3]) + (" ..." if len(answers) > 3 else "")
    if dns["malformed"]:
        text += f" (malformed: {dns['error']})"
    return text


def http_summary(http: dict) -> str:
    """Tóm tắt một dòng: " GET http://host/path" hoặc " 200 OK"."""
    if http["type"] == "request":
        req = http["request"]
        return f" {req['method']} {req.get('full_uri', req['uri'])}"
    if http["type"] == "response":
        res = http["response"]
        return f" {res['code']} {res['phrase']}".rstrip()
    return " (continuation)"


def check_source(args: argparse.Namespace) -> None:
    """Thoát với thông báo dễ hiểu nếu không đọc được nguồn gói."""
    if args.pcap:
        if not os.path.isfile(args.pcap):
            sys.exit(f"Không tìm thấy file PCAP: {args.pcap}")
        return
    interfaces = [name for _, name in socket.if_nameindex()]
    if args.interface not in interfaces:
        sys.exit(f"Không có interface {args.interface!r}. Các interface hiện có: {', '.join(interfaces)}")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        sys.exit("Live capture cần quyền root. Hãy chạy: sudo ./venv/bin/python main.py ...")


def main() -> None:
    parser = argparse.ArgumentParser(description="Packet Capture & Parser cho IDS")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--interface", "-i", help="Network interface để live capture")
    mode.add_argument("--pcap", "-r", help="File PCAP để đọc")
    parser.add_argument("--filter", help="BPF filter khi live capture, ví dụ 'tcp port 80'")
    parser.add_argument("--count", type=int, default=0, help="Số packet cần bắt (0 = vô hạn)")
    parser.add_argument("--output", "-o", default=DEFAULT_OUTPUT,
                        help=f"File JSON Lines để ghi kết quả (mặc định {DEFAULT_OUTPUT})")
    parser.add_argument("--append", action="store_true", help="Ghi tiếp vào file thay vì ghi đè")
    parser.add_argument("--skip-unknown", action="store_true",
                        help="Không ghi các gói thuộc giao thức không hỗ trợ (gói hỏng vẫn được ghi)")
    parser.add_argument("--max-payload", type=int, default=MAX_PAYLOAD_HEX,
                        help=f"Số byte payload tối đa ghi dạng hex (mặc định {MAX_PAYLOAD_HEX})")
    parser.add_argument("--quiet", "-q", action="store_true", help="Không in từng gói ra màn hình")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    # Scapy tự phân tích gói khi đọc và in cảnh báo về gói lạ (ví dụ vòng lặp nén DNS).
    # Chương trình chỉ lấy byte thô từ Scapy nên ẩn các cảnh báo đó; lỗi của Scapy vẫn hiện.
    logging.getLogger("scapy").setLevel(logging.ERROR)

    # Kiểm tra nguồn gói TRƯỚC khi mở file output, để gõ sai tên file hay interface
    # không làm ghi đè mất kết quả của lần chạy trước
    check_source(args)

    pipeline = Pipeline(skip_unknown=args.skip_unknown, max_payload=args.max_payload)
    with JsonlWriter(args.output, append=args.append) as writer:

        def handle(raw: RawPacket) -> None:
            # Cùng một hàm xử lý cho cả live và PCAP: chỉ có MỘT parsing pipeline
            event = pipeline.process(raw)
            if event is None:
                return
            writer.write(event)
            if not args.quiet:
                print(summarize(event), flush=True)

        try:
            if args.pcap:
                capture_pcap(args.pcap, handle)
            else:
                capture_live(args.interface, handle, args.filter, args.count)
        except KeyboardInterrupt:
            pass
        except FileNotFoundError:
            sys.exit(f"Không tìm thấy file PCAP: {args.pcap}")
        except PermissionError:
            sys.exit("Live capture cần quyền root. Hãy chạy: sudo ./venv/bin/python main.py ...")
        except (OSError, ValueError) as exc:
            # Ví dụ interface không tồn tại
            sys.exit(f"Không mở được interface {args.interface!r}: {exc}. "
                     f"Xem danh sách bằng lệnh: ip -br link")

    stats = pipeline.stats
    print(f"Đã xử lý {stats['total']} gói, ghi {writer.count} sự kiện vào {args.output} "
          f"(malformed: {stats['malformed']}, bỏ qua: {stats['skipped']})", file=sys.stderr)


if __name__ == "__main__":
    main()
