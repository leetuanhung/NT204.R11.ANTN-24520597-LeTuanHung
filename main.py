import argparse
import logging
import sys

from ids.capture import RawPacket, capture_live, capture_pcap
from ids.parsers.errors import ParseError
from ids.parsers.network import ETHERTYPE_IPV4, ETHERTYPE_NAMES, parse_ipv4, parse_link
from ids.parsers.transport import parse_tcp, parse_udp

IP_PROTO_TCP = 6
IP_PROTO_UDP = 17


class PacketPrinter:
    """Tạm thời: parse IPv4 và TCP rồi in một dòng mỗi gói.

    Bước sau sẽ thay bằng pipeline chính thức và ghi JSON Lines.
    """

    def __init__(self) -> None:
        self.packet_id = 0

    def __call__(self, raw: RawPacket) -> None:
        self.packet_id += 1
        try:
            line = self.describe(raw)
        except ParseError as exc:
            line = f"MALFORMED {exc}"
        except Exception as exc:   # Lỗi bất ngờ trong parser cũng không được làm dừng chương trình
            line = f"ERROR {type(exc).__name__}: {exc}"
        print(f"#{self.packet_id} {line}")

    @staticmethod
    def describe(raw: RawPacket) -> str:
        _, ethertype, l3 = parse_link(raw.data, raw.linktype)
        if ethertype != ETHERTYPE_IPV4:
            name = ETHERTYPE_NAMES.get(ethertype, f"0x{ethertype:04x}")
            return f"{name} UNKNOWN"

        ip, l4 = parse_ipv4(l3)
        note = " (truncated)" if ip["truncated"] else ""
        if ip["frag_offset"] > 0:
            return f"{ip['src']} -> {ip['dst']} IPv4 fragment offset={ip['frag_offset']}{note}"
        if ip["proto"] == IP_PROTO_UDP:
            udp, _ = parse_udp(l4)
            if udp["truncated"]:
                note = " (truncated)"
            return (f"{ip['src']}:{udp['srcport']} -> {ip['dst']}:{udp['dstport']} "
                    f"UDP len={udp['len']}{note}")
        if ip["proto"] != IP_PROTO_TCP:
            return f"{ip['src']} -> {ip['dst']} {ip['proto_name']} ttl={ip['ttl']}{note}"

        tcp, _ = parse_tcp(l4)
        return (f"{ip['src']}:{tcp['srcport']} -> {ip['dst']}:{tcp['dstport']} "
                f"TCP [{tcp['kind']}] seq={tcp['seq']} ack={tcp['ack']} "
                f"win={tcp['window_size_value']} len={tcp['len']}{note}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Packet Capture & Parser cho IDS")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--interface", "-i", help="Network interface để live capture")
    mode.add_argument("--pcap", "-r", help="File PCAP để đọc")
    parser.add_argument("--filter", help="BPF filter khi live capture, ví dụ 'tcp port 80'")
    parser.add_argument("--count", type=int, default=0, help="Số packet cần bắt (0 = vô hạn)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    handler = PacketPrinter()
    try:
        if args.pcap:
            capture_pcap(args.pcap, handler)
        else:
            capture_live(args.interface, handler, args.filter, args.count)
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
