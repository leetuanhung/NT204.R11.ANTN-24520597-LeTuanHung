"""Network parser: bỏ header lớp 2 rồi đọc header IPv4 từ byte thô.

Tên trường theo Wireshark display filter (https://www.wireshark.org/docs/dfref/i/ip.html),
bỏ tiền tố "ip." và đặt trong nhóm "ip". Ví dụ ip.flags.df -> ip["flags"]["df"].
"""

import socket
import struct

from ids.linktypes import (LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL,
                           LINKTYPE_LINUX_SLL2, LINKTYPE_RAW)
from ids.parsers.errors import ParseError

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = (0x8100, 0x88A8)   # 802.1Q và 802.1ad (QinQ)

ETHERTYPE_NAMES = {
    ETHERTYPE_IPV4: "IPv4",
    ETHERTYPE_ARP: "ARP",
    ETHERTYPE_IPV6: "IPv6",
    0x8100: "VLAN",
    0x88A8: "VLAN",
}

# Số protocol trong trường ip.proto (IANA)
IP_PROTO_NAMES = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6",
                  47: "GRE", 50: "ESP", 51: "AH", 89: "OSPF", 132: "SCTP"}

IPV4_MIN_HEADER = 20


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def parse_link(data: bytes, linktype: int) -> tuple[dict | None, int, bytes]:
    """Bỏ header lớp 2.

    Trả về (eth, ethertype, l3):
      eth       thông tin Ethernet (chỉ có với linktype Ethernet, còn lại là None)
      ethertype giao thức lớp 3, ví dụ 0x0800 là IPv4
      l3        phần byte bắt đầu từ header lớp 3
    """
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            raise ParseError(f"Ethernet: cần ít nhất 14 byte, chỉ có {len(data)}")
        dst, src, ethertype = data[0:6], data[6:12], struct.unpack("!H", data[12:14])[0]
        eth = {"dst": _mac(dst), "src": _mac(src), "type": ethertype}
        offset = 14
        # VLAN tag chèn 4 byte (TCI 2 byte + EtherType thật 2 byte). QinQ có thể lồng nhiều tag.
        vlans = []
        while ethertype in ETHERTYPE_VLAN:
            if len(data) < offset + 4:
                raise ParseError("Ethernet: VLAN tag bị cắt cụt")
            tci, ethertype = struct.unpack("!HH", data[offset:offset + 4])
            vlans.append(tci & 0x0FFF)   # 12 bit thấp là VLAN ID
            offset += 4
        if vlans:
            eth["vlan"] = vlans
            eth["type"] = ethertype
        return eth, ethertype, data[offset:]

    if linktype == LINKTYPE_RAW:
        if not data:
            raise ParseError("Raw IP: gói rỗng")
        version = data[0] >> 4
        ethertype = {4: ETHERTYPE_IPV4, 6: ETHERTYPE_IPV6}.get(version, 0)
        return None, ethertype, data

    if linktype == LINKTYPE_LINUX_SLL:
        # packet type(2) | ARPHRD(2) | addr len(2) | addr(8) | protocol(2)
        if len(data) < 16:
            raise ParseError(f"Linux SLL: cần ít nhất 16 byte, chỉ có {len(data)}")
        return None, struct.unpack("!H", data[14:16])[0], data[16:]

    if linktype == LINKTYPE_LINUX_SLL2:
        # protocol(2) | reserved(2) | ifindex(4) | ARPHRD(2) | pkttype(1) | addr len(1) | addr(8)
        if len(data) < 20:
            raise ParseError(f"Linux SLL2: cần ít nhất 20 byte, chỉ có {len(data)}")
        return None, struct.unpack("!H", data[0:2])[0], data[20:]

    raise ParseError(f"Linktype {linktype} chưa được hỗ trợ")


def ipv4_checksum(header: bytes) -> int:
    """Tổng bù một (one's complement) của các từ 16 bit trong header.

    Khi tính trên header có sẵn checksum, kết quả đúng phải bằng 0.
    """
    if len(header) % 2:
        header += b"\x00"
    total = sum(struct.unpack(f"!{len(header) // 2}H", header))
    while total >> 16:                   # Cộng phần tràn vào lại 16 bit thấp
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def parse_ipv4(data: bytes) -> tuple[dict, bytes]:
    """Đọc header IPv4. Trả về (ip, payload) với payload là dữ liệu tầng 4."""
    if len(data) < IPV4_MIN_HEADER:
        raise ParseError(f"IPv4: cần ít nhất {IPV4_MIN_HEADER} byte, chỉ có {len(data)}")

    (ver_ihl, dsfield, total_len, ident, flags_frag,
     ttl, proto, checksum, src, dst) = struct.unpack("!BBHHHBBH4s4s", data[:20])

    version = ver_ihl >> 4
    if version != 4:
        raise ParseError(f"IPv4: version phải là 4, gặp {version}")

    ihl = ver_ihl & 0x0F                  # Đơn vị là từ 4 byte
    hdr_len = ihl * 4
    if ihl < 5:
        raise ParseError(f"IPv4: IHL={ihl} nhỏ hơn 5 (header tối thiểu 20 byte)")
    if len(data) < hdr_len:
        raise ParseError(f"IPv4: header dài {hdr_len} byte nhưng chỉ có {len(data)}")
    if total_len < hdr_len:
        raise ParseError(f"IPv4: total length {total_len} nhỏ hơn header {hdr_len}")

    flags = flags_frag >> 13              # 3 bit cao
    frag_offset = (flags_frag & 0x1FFF) * 8   # Wireshark hiển thị theo byte
    mf = bool(flags & 0b001)

    ip = {
        "version": version,
        "hdr_len": hdr_len,
        "dsfield": dsfield,
        "dsfield_dscp": dsfield >> 2,
        "dsfield_ecn": dsfield & 0b11,
        "len": total_len,
        "id": ident,
        "flags": {
            "rb": bool(flags & 0b100),
            "df": bool(flags & 0b010),
            "mf": mf,
        },
        "frag_offset": frag_offset,
        "is_fragment": mf or frag_offset > 0,
        "ttl": ttl,
        "proto": proto,
        "proto_name": IP_PROTO_NAMES.get(proto, "UNKNOWN"),
        "checksum": checksum,
        "checksum_status": "good" if ipv4_checksum(data[:hdr_len]) == 0 else "bad",
        "src": socket.inet_ntoa(src),
        "dst": socket.inet_ntoa(dst),
        "options_len": hdr_len - IPV4_MIN_HEADER,
        "truncated": False,
    }

    if total_len > len(data):
        # Gói bị cắt (snaplen nhỏ hoặc PCAP hỏng): vẫn trả phần đọc được
        ip["truncated"] = True
    # Cắt theo total length để bỏ byte đệm Ethernet ở cuối frame
    payload = data[hdr_len:total_len]
    return ip, payload
