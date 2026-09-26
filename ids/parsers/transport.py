"""Transport parser: đọc header TCP và UDP từ byte thô.

Tên trường theo Wireshark display filter
(https://www.wireshark.org/docs/dfref/t/tcp.html, https://www.wireshark.org/docs/dfref/u/udp.html),
bỏ tiền tố "tcp." / "udp." và đặt trong nhóm tương ứng. Ví dụ tcp.flags.syn -> tcp["flags"]["syn"].
"""

import struct

from ids.parsers.errors import ParseError

TCP_MIN_HEADER = 20
UDP_HEADER = 8
MAX_PAYLOAD_HEX = 1024     # Số byte payload tối đa ghi ra dưới dạng hex

# (tên trường Wireshark, bit trong 12 bit flags, ký tự viết tắt, nhãn in hoa)
# Thứ tự ký tự giống Scapy: F S R P A U E C N
TCP_FLAGS = [
    ("fin",   0x001, "F", "FIN"),
    ("syn",   0x002, "S", "SYN"),
    ("reset", 0x004, "R", "RST"),
    ("push",  0x008, "P", "PSH"),
    ("ack",   0x010, "A", "ACK"),
    ("urg",   0x020, "U", "URG"),
    ("ece",   0x040, "E", "ECE"),
    ("cwr",   0x080, "C", "CWR"),
    ("ae",    0x100, "N", "AE"),    # Accurate ECN (trước đây gọi là NS)
]

# Thứ tự in nhãn cho dễ đọc: SYN/ACK, FIN/ACK, PSH/ACK...
_KIND_ORDER = ["syn", "fin", "reset", "push", "ack", "urg", "ece", "cwr", "ae"]
_LABEL = {name: label for name, _, _, label in TCP_FLAGS}

# Mã kind của TCP option (IANA)
OPT_EOL, OPT_NOP, OPT_MSS, OPT_WSCALE, OPT_SACK_PERM, OPT_SACK, OPT_TIMESTAMP = 0, 1, 2, 3, 4, 5, 8


def _payload_fields(payload: bytes, max_payload: int) -> dict:
    """Các trường mô tả payload, dùng chung cho TCP và UDP.

    Chỉ ghi tối đa max_payload byte dưới dạng hex để file log không phình to;
    payload đầy đủ vẫn được trả về riêng cho tầng ứng dụng.
    """
    return {
        "len": len(payload),
        "payload": payload[:max_payload].hex(),
        "payload_truncated": len(payload) > max_payload,
    }


def parse_tcp_options(raw: bytes) -> dict:
    """Đọc vùng option dạng TLV: kind(1) | length(1) | value(length-2).

    Riêng EOL (0) và NOP (1) chỉ có 1 byte kind, không có length.
    Option hỏng thì dừng đọc và đánh dấu malformed, không làm hỏng cả gói.
    """
    opts = {"kinds": []}
    i = 0
    while i < len(raw):
        kind = raw[i]
        opts["kinds"].append(kind)
        if kind == OPT_EOL:
            break
        if kind == OPT_NOP:
            i += 1
            continue
        if i + 1 >= len(raw):
            opts["malformed"] = True
            break
        length = raw[i + 1]
        if length < 2 or i + length > len(raw):
            opts["malformed"] = True
            break
        value = raw[i + 2:i + length]

        if kind == OPT_MSS and length == 4:
            opts["mss_val"] = struct.unpack("!H", value)[0]
        elif kind == OPT_WSCALE and length == 3:
            opts["wscale_shift"] = value[0]
            opts["wscale_multiplier"] = 1 << min(value[0], 14)   # RFC 7323: tối đa 14
        elif kind == OPT_SACK_PERM and length == 2:
            opts["sack_perm"] = True
        elif kind == OPT_SACK and (length - 2) % 8 == 0:
            opts["sack"] = [list(struct.unpack("!II", value[j:j + 8]))
                            for j in range(0, len(value), 8)]
        elif kind == OPT_TIMESTAMP and length == 10:
            opts["timestamp_tsval"], opts["timestamp_tsecr"] = struct.unpack("!II", value)
        i += length
    return opts


def tcp_packet_kind(flags: dict) -> str:
    """Nhãn dễ đọc từ các cờ, ví dụ "SYN", "SYN/ACK", "PSH/ACK", "FIN/ACK".

    Gói không bật cờ nào (NULL scan) trả về "NULL".
    """
    labels = [_LABEL[name] for name in _KIND_ORDER if flags.get(name)]
    return "/".join(labels) if labels else "NULL"


def parse_tcp(data: bytes, max_payload: int = MAX_PAYLOAD_HEX) -> tuple[dict, bytes]:
    """Đọc header TCP. Trả về (tcp, payload) với payload là dữ liệu tầng ứng dụng."""
    if len(data) < TCP_MIN_HEADER:
        raise ParseError(f"TCP: cần ít nhất {TCP_MIN_HEADER} byte, chỉ có {len(data)}")

    (srcport, dstport, seq, ack, off_flags,
     window, checksum, urgent) = struct.unpack("!HHIIHHHH", data[:20])

    data_offset = off_flags >> 12          # 4 bit cao, đơn vị là từ 4 byte
    hdr_len = data_offset * 4
    if data_offset < 5:
        raise ParseError(f"TCP: data offset={data_offset} nhỏ hơn 5 (header tối thiểu 20 byte)")
    if len(data) < hdr_len:
        raise ParseError(f"TCP: header dài {hdr_len} byte nhưng chỉ có {len(data)}")

    bits = off_flags & 0x1FF               # 9 bit cờ thấp nhất
    flags = {name: bool(bits & mask) for name, mask, _, _ in TCP_FLAGS}
    flags["str"] = "".join(ch for name, mask, ch, _ in TCP_FLAGS if bits & mask)
    flags["value"] = bits

    payload = data[hdr_len:]
    tcp = {
        "srcport": srcport,
        "dstport": dstport,
        "seq": seq,              # Số thô; Wireshark mặc định hiển thị số tương đối
        "ack": ack,
        "hdr_len": hdr_len,
        "flags": flags,
        "kind": tcp_packet_kind(flags),
        "window_size_value": window,
        # Không kiểm tra checksum TCP vì cần pseudo-header (IP nguồn, đích, độ dài)
        # và nhiều card mạng tự tính checksum khi gửi (checksum offload)
        "checksum": checksum,
        "urgent_pointer": urgent,
        "options": parse_tcp_options(data[TCP_MIN_HEADER:hdr_len]),
        **_payload_fields(payload, max_payload),
    }
    return tcp, payload


def parse_udp(data: bytes, max_payload: int = MAX_PAYLOAD_HEX) -> tuple[dict, bytes]:
    """Đọc header UDP 8 byte. Trả về (udp, payload).

    Header: srcport(2) | dstport(2) | length(2) | checksum(2)
    Trường length tính cả 8 byte header, nên payload dài length - 8.
    """
    if len(data) < UDP_HEADER:
        raise ParseError(f"UDP: cần ít nhất {UDP_HEADER} byte, chỉ có {len(data)}")

    srcport, dstport, length, checksum = struct.unpack("!HHHH", data[:UDP_HEADER])
    if length < UDP_HEADER:
        raise ParseError(f"UDP: length={length} nhỏ hơn header {UDP_HEADER} byte")

    # length lớn hơn số byte có được: gói bị cắt, lấy phần còn lại.
    # length nhỏ hơn: các byte thừa phía sau không thuộc gói UDP nên bỏ đi.
    truncated = length > len(data)
    payload = data[UDP_HEADER:length]

    udp = {
        "srcport": srcport,
        "dstport": dstport,
        "length": length,
        # Không kiểm tra checksum, cùng lý do như TCP (cần pseudo-header, checksum offload).
        # Riêng giá trị 0 trong IPv4 nghĩa là người gửi không tính checksum (RFC 768).
        "checksum": checksum,
        "checksum_zero": checksum == 0,
        "truncated": truncated,
        **_payload_fields(payload, max_payload),
    }
    return udp, payload
