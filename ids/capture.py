"""Packet capture: live interface hoặc file PCAP.

Cả hai nguồn đều chuyển packet thành cùng một kiểu RawPacket
(timestamp + raw bytes + linktype) rồi gọi chung một handler.
Nhờ vậy phía sau chỉ có MỘT parsing pipeline cho cả live lẫn PCAP.
"""

import logging
from dataclasses import dataclass
from typing import Callable

from scapy.all import PcapReader, sniff
from scapy.error import Scapy_Exception

from ids.linktypes import (LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL,
                           LINKTYPE_LINUX_SLL2, LINKTYPE_RAW)

log = logging.getLogger(__name__)

# Tên lớp Scapy của layer đầu tiên -> linktype (dùng cho live capture)
_LAYER_TO_LINKTYPE = {
    "Ether": LINKTYPE_ETHERNET,
    "CookedLinux": LINKTYPE_LINUX_SLL,
    "CookedLinuxV2": LINKTYPE_LINUX_SLL2,
    "IP": LINKTYPE_RAW,
}


@dataclass
class RawPacket:
    timestamp: float    # Thời điểm packet được thu nhận (epoch, giây)
    data: bytes         # Toàn bộ byte của frame
    linktype: int       # Kiểu header lớp 2 để parser biết IP bắt đầu ở đâu
    source: str         # "live:<iface>" hoặc "pcap:<file>"


PacketHandler = Callable[[RawPacket], None]


def _to_raw(pkt, linktype: int, source: str) -> RawPacket:
    return RawPacket(
        timestamp=float(pkt.time),
        data=bytes(pkt),
        linktype=linktype,
        source=source,
    )


def capture_live(interface: str, handler: PacketHandler,
                 bpf_filter: str | None = None, count: int = 0) -> None:
    """Bắt packet trên interface và đẩy NGAY từng packet vào handler."""
    source = f"live:{interface}"

    def on_packet(pkt):
        linktype = _LAYER_TO_LINKTYPE.get(type(pkt).__name__, LINKTYPE_ETHERNET)
        try:
            handler(_to_raw(pkt, linktype, source))
        except Exception:  # Một packet lỗi không được làm dừng capture
            log.exception("Lỗi khi xử lý packet live")

    # store=False: không giữ packet trong RAM, xử lý xong là bỏ
    sniff(iface=interface, prn=on_packet, store=False,
          filter=bpf_filter, count=count)


def capture_pcap(path: str, handler: PacketHandler) -> None:
    """Đọc file PCAP/PCAPNG và đẩy từng packet vào cùng handler."""
    source = f"pcap:{path}"
    try:
        reader = PcapReader(path)
    except (Scapy_Exception, EOFError) as exc:
        # File rỗng hoặc không phải định dạng PCAP/PCAPNG: báo lỗi, không crash.
        # FileNotFoundError vẫn được ném ra để main.py báo cho người dùng.
        log.error("Không đọc được %s: %s", path, exc)
        return
    with reader:
        linktype = getattr(reader, "linktype", LINKTYPE_ETHERNET)
        while True:
            try:
                pkt = next(reader)
            except StopIteration:
                break
            except (EOFError, Scapy_Exception, OSError, ValueError) as exc:
                # File bị cắt cụt (truncated) ở giữa packet: dừng êm, không crash
                log.warning("PCAP bị hỏng hoặc truncated, dừng đọc: %s", exc)
                break
            try:
                handler(_to_raw(pkt, linktype, source))
            except Exception:
                log.exception("Lỗi khi xử lý packet từ PCAP")
