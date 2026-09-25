import argparse
import logging
import sys

from ids.capture import RawPacket, capture_live, capture_pcap


def print_packet(raw: RawPacket) -> None:
    # Tạm thời chỉ in ra để kiểm tra capture. Sẽ thay bằng parsing pipeline.
    print(f"{raw.timestamp:.6f} {raw.source} linktype={raw.linktype} len={len(raw.data)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Packet Capture & Parser cho IDS")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--interface", "-i", help="Network interface để live capture")
    mode.add_argument("--pcap", "-r", help="File PCAP để đọc")
    parser.add_argument("--filter", help="BPF filter khi live capture, ví dụ 'tcp port 80'")
    parser.add_argument("--count", type=int, default=0, help="Số packet cần bắt (0 = vô hạn)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    try:
        if args.pcap:
            capture_pcap(args.pcap, print_packet)
        else:
            capture_live(args.interface, print_packet, args.filter, args.count)
    except KeyboardInterrupt:
        pass
    except FileNotFoundError:
        sys.exit(f"Không tìm thấy file PCAP: {args.pcap}")
    except PermissionError:
        sys.exit("Live capture cần quyền root. Hãy chạy: sudo ./venv/bin/python main.py ...")
    except (OSError, ValueError) as exc:
        # Ví dụ interface không tồn tại
        sys.exit(f"Không mở được interface {args.interface!r}: {exc}. Xem danh sách bằng lệnh: ip -br link")


if __name__ == "__main__":
    main()
