"""DNS parser: đọc header, câu hỏi và các bản ghi trả lời từ payload UDP hoặc TCP.

Tên trường theo Wireshark display filter (https://www.wireshark.org/docs/dfref/d/dns.html),
bỏ tiền tố "dns." và đặt trong nhóm "dns". Ví dụ dns.qry.name -> dns["qry"][0]["name"],
dns.flags.rcode -> dns["flags"]["rcode"].

Nguyên tắc xử lý lỗi:
  - Header hỏng (thiếu 12 byte đầu) -> ParseError, vì không đọc được gì.
  - Lỗi ở phần câu hỏi hoặc bản ghi -> dừng đọc, đặt malformed = True kèm lý do,
    GIỮ LẠI các phần đã đọc được. IDS vẫn có thông tin để phân tích.
"""

import socket
import struct

from ids.parsers.errors import ParseError

DNS_HEADER = 12
MAX_NAME_LEN = 255          # RFC 1035: tên miền tối đa 255 byte
MAX_POINTER_JUMPS = 64      # Chặn vòng lặp con trỏ nén
MAX_RDATA_HEX = 256         # Dữ liệu của kiểu bản ghi chưa hỗ trợ: ghi tối đa 256 byte dạng hex
# Tổng số bước (nhãn + con trỏ) được phép đọc trong MỘT thông điệp. Gói 64 KB có thể chứa hàng
# nghìn bản ghi cùng trỏ về một tên dài 127 nhãn, bắt parser làm hàng trăm nghìn bước.
# Thông điệp bình thường chỉ cần vài trăm bước, nên giới hạn này không ảnh hưởng gói hợp lệ.
MAX_NAME_STEPS = 20000

OPCODE_NAMES = {0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE", 6: "DSO"}
RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
               5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH",
               10: "NOTZONE"}
TYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX",
              16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 41: "OPT", 43: "DS",
              46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS",
              251: "IXFR", 252: "AXFR", 255: "ANY", 257: "CAA"}
CLASS_NAMES = {1: "IN", 3: "CH", 4: "HS", 254: "NONE", 255: "ANY"}

SECTIONS = ("answer", "authority", "additional")


class _Malformed(Exception):
    """Lỗi bên trong phần câu hỏi/bản ghi. Chỉ dùng nội bộ để dừng vòng đọc."""


class _Budget:
    """Đếm số bước đọc tên còn lại của một thông điệp, chống tấn công làm chậm parser."""

    def __init__(self, limit: int = MAX_NAME_STEPS) -> None:
        self.left = limit

    def spend(self) -> None:
        self.left -= 1
        if self.left < 0:
            raise _Malformed(f"Vượt quá {MAX_NAME_STEPS} bước giải nén tên trong một thông điệp")


def _need(msg: bytes, off: int, n: int, what: str) -> None:
    if off + n > len(msg):
        raise _Malformed(f"{what}: cần {n} byte tại vị trí {off}, chỉ còn {max(len(msg) - off, 0)}")


def _label_text(label: bytes) -> str:
    """Đổi một nhãn sang chuỗi theo quy ước file zone (RFC 1035 mục 5.1).

    Ký tự in được giữ nguyên; dấu chấm và dấu gạch chéo trong nhãn được thêm "\\" phía trước;
    byte khác viết thành \\DDD. Nhờ vậy tên chứa byte lạ (thường gặp khi DNS tunneling)
    vẫn hiển thị được và không làm hỏng JSON.
    """
    out = []
    for b in label:
        ch = chr(b)
        if ch in ".\\":
            out.append("\\" + ch)
        elif 0x21 <= b <= 0x7E:
            out.append(ch)
        else:
            out.append(f"\\{b:03d}")
    return "".join(out)


def read_name(msg: bytes, off: int, budget: _Budget | None = None) -> tuple[str, int]:
    """Đọc tên miền bắt đầu tại off. Trả về (tên, vị trí ngay sau tên trong bản gốc).

    Tên gồm các nhãn [độ dài 1 byte][nội dung], kết thúc bằng byte 0.
    Nếu 2 bit cao của byte độ dài là 11 thì đó là con trỏ nén 14 bit: phần còn lại
    của tên nằm ở vị trí khác trong gói. Sau con trỏ, tên kết thúc.
    """
    labels = []
    wire_len = 1                   # Byte 0 kết thúc
    end = None                     # Vị trí sau tên trong bản gốc (trước lần nhảy đầu tiên)
    jumps = 0
    visited = set()
    while True:
        if budget is not None:
            budget.spend()
        _need(msg, off, 1, "Tên miền")
        length = msg[off]
        kind = length & 0xC0
        if kind == 0xC0:           # Con trỏ nén
            _need(msg, off, 2, "Con trỏ nén")
            target = struct.unpack("!H", msg[off:off + 2])[0] & 0x3FFF
            if end is None:
                end = off + 2
            jumps += 1
            if target in visited or jumps > MAX_POINTER_JUMPS:
                raise _Malformed(f"Con trỏ nén tạo vòng lặp tại vị trí {off}")
            if target >= len(msg):
                raise _Malformed(f"Con trỏ nén trỏ ra ngoài gói ({target})")
            visited.add(target)
            off = target
            continue
        if kind:                   # 01 và 10: kiểu nhãn đã bỏ, không dùng
            raise _Malformed(f"Kiểu nhãn không hợp lệ 0x{length:02x} tại vị trí {off}")
        if length == 0:
            if end is None:
                end = off + 1
            break
        _need(msg, off + 1, length, "Nhãn")
        labels.append(_label_text(msg[off + 1:off + 1 + length]))
        wire_len += length + 1
        if wire_len > MAX_NAME_LEN:
            raise _Malformed(f"Tên miền dài hơn {MAX_NAME_LEN} byte")
        off += 1 + length
    return (".".join(labels) if labels else "<Root>"), end


def _read_character_strings(rdata: bytes) -> list[str]:
    """TXT gồm nhiều chuỗi, mỗi chuỗi [độ dài 1 byte][nội dung]."""
    out, i = [], 0
    while i < len(rdata):
        n = rdata[i]
        if i + 1 + n > len(rdata):
            raise _Malformed("TXT: chuỗi vượt quá độ dài bản ghi")
        out.append(rdata[i + 1:i + 1 + n].decode("utf-8", errors="replace"))
        i += 1 + n
    return out


def _parse_rdata(msg: bytes, rtype: int, start: int, rdlen: int, rr: dict,
                 budget: _Budget) -> None:
    """Đọc phần dữ liệu (RDATA) theo kiểu bản ghi, ghi thẳng vào rr.

    Tên miền trong RDATA có thể dùng con trỏ nén trỏ ra chỗ khác trong gói,
    nhưng phần byte nằm tại chỗ phải gói gọn trong rdlen.
    """
    end = start + rdlen
    rdata = msg[start:end]

    def name_at(off: int) -> tuple[str, int]:
        name, after = read_name(msg, off, budget)
        if after > end:
            raise _Malformed("Tên miền trong RDATA vượt quá độ dài bản ghi")
        return name, after

    def fixed(n: int) -> None:
        if rdlen != n:
            raise _Malformed(f"{TYPE_NAMES.get(rtype, rtype)}: độ dài phải là {n}, gặp {rdlen}")

    if rtype == 1:                                       # A
        fixed(4)
        rr["a"] = socket.inet_ntoa(rdata)
    elif rtype == 28:                                    # AAAA
        fixed(16)
        rr["aaaa"] = socket.inet_ntop(socket.AF_INET6, rdata)
    elif rtype in (2, 5, 12):                            # NS, CNAME, PTR
        key = {2: "ns", 5: "cname", 12: "ptr"}[rtype]
        rr[key], _ = name_at(start)
    elif rtype == 15:                                    # MX
        if rdlen < 3:
            raise _Malformed("MX: quá ngắn")
        name, _ = name_at(start + 2)
        rr["mx"] = {"preference": struct.unpack("!H", rdata[:2])[0], "mail_exchange": name}
    elif rtype == 16:                                    # TXT
        rr["txt"] = _read_character_strings(rdata)
    elif rtype == 6:                                     # SOA
        mname, off = name_at(start)
        rname, off = name_at(off)
        if off + 20 > end:
            raise _Malformed("SOA: thiếu 5 trường số")
        serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", msg[off:off + 20])
        rr["soa"] = {"mname": mname, "rname": rname, "serial_number": serial,
                     "refresh_interval": refresh, "retry_interval": retry,
                     "expire_limit": expire, "minimum_ttl": minimum}
    elif rtype == 33:                                    # SRV
        if rdlen < 7:
            raise _Malformed("SRV: quá ngắn")
        priority, weight, port = struct.unpack("!HHH", rdata[:6])
        target, _ = name_at(start + 6)
        rr["srv"] = {"priority": priority, "weight": weight, "port": port, "target": target}
    else:                                                # Kiểu chưa hỗ trợ: giữ dạng hex
        rr["data"] = rdata[:MAX_RDATA_HEX].hex()


def _parse_question(msg: bytes, off: int, budget: _Budget) -> tuple[dict, int]:
    name, off = read_name(msg, off, budget)
    _need(msg, off, 4, "Câu hỏi")
    qtype, qclass = struct.unpack("!HH", msg[off:off + 4])
    q = {
        "name": name,
        "type": qtype,
        "type_name": TYPE_NAMES.get(qtype, f"TYPE{qtype}"),
        "class": qclass & 0x7FFF,
        "class_name": CLASS_NAMES.get(qclass & 0x7FFF, f"CLASS{qclass & 0x7FFF}"),
    }
    if qclass & 0x8000:
        q["unicast_response"] = True        # mDNS: bit cao của class là cờ QU
    return q, off + 4


def _parse_record(msg: bytes, off: int, section: str, budget: _Budget) -> tuple[dict, int]:
    name, off = read_name(msg, off, budget)
    _need(msg, off, 10, "Bản ghi")
    rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
    off += 10
    _need(msg, off, rdlen, "RDATA")

    rr = {"section": section, "name": name, "type": rtype,
          "type_name": TYPE_NAMES.get(rtype, f"TYPE{rtype}")}
    if rtype == 41:
        # OPT (EDNS0, RFC 6891): class là kích thước gói UDP, TTL chứa rcode mở rộng, version, cờ DO
        rr["opt"] = {"udp_payload_size": rclass, "ext_rcode": ttl >> 24,
                     "version": (ttl >> 16) & 0xFF, "do": bool(ttl & 0x8000)}
        rr["len"] = rdlen
        return rr, off + rdlen

    rr["class"] = rclass & 0x7FFF
    rr["class_name"] = CLASS_NAMES.get(rclass & 0x7FFF, f"CLASS{rclass & 0x7FFF}")
    if rclass & 0x8000:
        rr["cache_flush"] = True            # mDNS: bit cao của class là cờ cache-flush
    rr["ttl"] = ttl
    rr["len"] = rdlen
    try:
        _parse_rdata(msg, rtype, off, rdlen, rr, budget)
    except _Malformed as exc:
        if budget.left < 0:
            raise                   # Hết ngân sách thì dừng cả thông điệp, không đọc tiếp
        # rdlen cho biết bản ghi kết thúc ở đâu, nên RDATA hỏng không làm hỏng các bản ghi sau
        rr["rdata_malformed"] = str(exc)
        rr["data"] = msg[off:off + rdlen][:MAX_RDATA_HEX].hex()
    return rr, off + rdlen


def parse_dns(payload: bytes, transport: str = "UDP") -> dict:
    """Parse một thông điệp DNS. transport = "TCP" thì bỏ 2 byte độ dài ở đầu."""
    dns: dict = {}
    msg = payload
    if transport == "TCP":
        if len(payload) < 2:
            raise ParseError("DNS: thiếu 2 byte độ dài của DNS qua TCP")
        length = struct.unpack("!H", payload[:2])[0]
        msg = payload[2:2 + length]
        dns["tcp_length"] = length
        dns["message_truncated"] = length > len(payload) - 2

    if len(msg) < DNS_HEADER:
        raise ParseError(f"DNS: cần ít nhất {DNS_HEADER} byte header, chỉ có {len(msg)}")

    ident, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", msg[:DNS_HEADER])
    opcode = (flags >> 11) & 0xF
    rcode = flags & 0xF
    dns.update({
        "id": ident,
        "flags": {
            "value": flags,
            "response": bool(flags & 0x8000),
            "opcode": opcode,
            "opcode_name": OPCODE_NAMES.get(opcode, f"OPCODE{opcode}"),
            "authoritative": bool(flags & 0x0400),
            "truncated": bool(flags & 0x0200),
            "recdesired": bool(flags & 0x0100),
            "recavail": bool(flags & 0x0080),
            "z": bool(flags & 0x0040),
            "authenticated": bool(flags & 0x0020),
            "checkdisable": bool(flags & 0x0010),
            "rcode": rcode,
            "rcode_name": RCODE_NAMES.get(rcode, f"RCODE{rcode}"),
        },
        "count": {"queries": qd, "answers": an, "auth_rr": ns, "add_rr": ar},
        "qry": [],
        "resp": [],
        "malformed": False,
    })

    off = DNS_HEADER
    budget = _Budget()
    try:
        for _ in range(qd):
            q, off = _parse_question(msg, off, budget)
            dns["qry"].append(q)
        for section, count in zip(SECTIONS, (an, ns, ar)):
            for _ in range(count):
                rr, off = _parse_record(msg, off, section, budget)
                dns["resp"].append(rr)
    except _Malformed as exc:
        dns["malformed"] = True
        dns["error"] = str(exc)

    if not dns["malformed"] and off < len(msg):
        dns["trailing_bytes"] = len(msg) - off     # Byte thừa sau bản ghi cuối: bất thường
    return dns
