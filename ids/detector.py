"""Application Protocol Detector: đoán gói thuộc HTTP, DNS hay SMTP.

Kết hợp hai loại tín hiệu (mục 5 của đề):
  - Payload: nội dung đầu payload có đúng "hình dạng" của giao thức không.
  - Port: port chuẩn của giao thức, chỉ là tín hiệu phụ.

Payload được ưu tiên hơn port, nên nhận đúng giao thức chạy trên port không chuẩn
(ví dụ HTTP trên port 12345). Detector chỉ đọc phần đầu payload để phân loại;
việc tách từng trường là của parser HTTP, DNS, SMTP ở các bước sau.
"""

import re
import struct
from typing import NamedTuple

HTTP, DNS, SMTP, UNKNOWN = "HTTP", "DNS", "SMTP", "UNKNOWN"

# Port chuẩn của từng giao thức và tầng transport mà giao thức đó chạy trên.
# Không có 443 (HTTPS) và 465 (SMTPS) vì dữ liệu đã mã hóa TLS, không đọc được.
PORTS = {
    HTTP: ({80, 8080, 8000, 8008, 8888}, {"TCP"}),
    DNS:  ({53, 5353, 5355}, {"UDP", "TCP"}),   # 5353: mDNS, 5355: LLMNR (cùng định dạng DNS)
    SMTP: ({25, 587, 2525}, {"TCP"}),
}

# ---- Chữ ký HTTP (RFC 9112) ----
# Request line: METHOD SP request-target SP HTTP-version CRLF. Method phân biệt hoa thường.
_HTTP_REQUEST = re.compile(
    rb"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) \S+ HTTP/1\.[01](?:\r?\n|$)")
# Status line: HTTP-version SP status-code(100-599) ...
_HTTP_RESPONSE = re.compile(rb"HTTP/1\.[01] [1-5]\d\d(?: |\r?\n|$)")

# ---- Chữ ký SMTP (RFC 5321), lệnh không phân biệt hoa thường ----
# Tín hiệu mạnh: chỉ SMTP mới dùng, đủ để kết luận ở bất kỳ port nào.
_SMTP_STRONG = [
    re.compile(rb"(?:HELO|EHLO) \S+", re.IGNORECASE),
    re.compile(rb"(?:MAIL FROM|RCPT TO):", re.IGNORECASE),
    re.compile(rb"220[ -][^\r\n]*SMTP", re.IGNORECASE),     # Banner, ví dụ "220 mx ESMTP Postfix"
]
# Tín hiệu yếu: FTP, POP3 cũng có lệnh/phản hồi giống vậy, nên chỉ tính khi port cũng là SMTP.
_SMTP_WEAK = [
    re.compile(rb"(?:DATA|QUIT|RSET|NOOP|VRFY|EXPN|HELP|AUTH|STARTTLS|BDAT)(?: |\r?\n|$)",
               re.IGNORECASE),
    re.compile(rb"[1-5]\d\d(?:[ -]|\r?\n|$)"),                # Phản hồi "250 OK", "354 ..."
]

# ---- Kiểm tra định dạng DNS (RFC 1035) ----
DNS_HEADER = 12
_DNS_OPCODES = {0, 1, 2, 4, 5, 6}        # QUERY, IQUERY, STATUS, NOTIFY, UPDATE, DSO
_DNS_CLASSES = {1, 3, 4, 255}            # IN, CHAOS, HESIOD, ANY
_MAX_QDCOUNT = 16


class Detection(NamedTuple):
    protocol: str | None      # "HTTP", "DNS", "SMTP", "UNKNOWN", hoặc None nếu không có payload
    detected_by: str | None   # "payload+port", "payload", "port", hoặc None


def _skip_dns_name(msg: bytes, off: int) -> int | None:
    """Đi qua một tên miền dạng nhãn, trả về vị trí ngay sau tên, hoặc None nếu sai định dạng.

    Tên gồm các nhãn: 1 byte độ dài (0-63) rồi đến nội dung, kết thúc bằng byte 0.
    Hai bit cao 11 nghĩa là con trỏ nén 2 byte, chỉ được trỏ lùi về phần đã đọc.
    """
    start, total = off, 0
    while off < len(msg):
        length = msg[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:                      # Con trỏ nén
            if off + 1 >= len(msg):
                return None
            target = struct.unpack("!H", msg[off:off + 2])[0] & 0x3FFF
            # Phải trỏ lùi vào vùng sau header, không được trỏ vào chính nó hay về sau
            return off + 2 if DNS_HEADER <= target < start else None
        if length & 0xC0:                              # 01 và 10 là kiểu nhãn không dùng
            return None
        total += length + 1
        if total > 255:                                # Tên tối đa 255 byte
            return None
        off += 1 + length
    return None                                        # Hết dữ liệu mà chưa gặp byte 0


def looks_like_dns(msg: bytes) -> bool:
    """Kiểm tra nhanh msg có phải một thông điệp DNS hợp lệ không (không parse hết)."""
    if len(msg) < DNS_HEADER:
        return False
    _, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", msg[:DNS_HEADER])
    is_response = bool(flags & 0x8000)
    opcode = (flags >> 11) & 0xF
    if opcode not in _DNS_OPCODES:
        return False
    if qd > _MAX_QDCOUNT:
        return False
    # Mỗi câu hỏi tối thiểu 5 byte, mỗi bản ghi tối thiểu 11 byte: số lượng khai báo phải vừa gói
    if qd * 5 + (an + ns + ar) * 11 > len(msg) - DNS_HEADER:
        return False

    if qd > 0:                                  # Kiểm tra câu hỏi đầu tiên: name, type, class
        need_after_name = 4
    elif is_response and an > 0:                # mDNS thường gửi trả lời không kèm câu hỏi
        need_after_name = 10                    # type, class, ttl, rdlength
    else:
        return False

    off = _skip_dns_name(msg, DNS_HEADER)
    if off is None or off + need_after_name > len(msg):
        return False
    rclass = struct.unpack("!H", msg[off + 2:off + 4])[0] & 0x7FFF   # Bỏ bit cờ của mDNS
    return rclass in _DNS_CLASSES


def _dns_message(transport: str, payload: bytes) -> bytes | None:
    """DNS qua TCP có thêm 2 byte độ dài ở đầu (RFC 1035 mục 4.2.2); UDP thì không."""
    if transport != "TCP":
        return payload
    if len(payload) < 2 + DNS_HEADER:
        return None
    length = struct.unpack("!H", payload[:2])[0]
    if length < DNS_HEADER:
        return None
    return payload[2:2 + length]


def _strong_match(transport: str, payload: bytes) -> str | None:
    """Tín hiệu payload mạnh: đủ để kết luận mà không cần port."""
    if transport == "TCP":
        if _HTTP_REQUEST.match(payload) or _HTTP_RESPONSE.match(payload):
            return HTTP
        if any(p.match(payload) for p in _SMTP_STRONG):
            return SMTP
    msg = _dns_message(transport, payload)
    if msg is not None and looks_like_dns(msg):
        return DNS
    return None


def _port_protocols(transport: str, srcport: int, dstport: int) -> list[str]:
    """Các giao thức mà port gợi ý, ưu tiên port đích (gói request) rồi đến port nguồn (gói response)."""
    found = []
    for port in (dstport, srcport):
        for proto, (ports, transports) in PORTS.items():
            if port in ports and transport in transports and proto not in found:
                found.append(proto)
    return found


def detect_app(transport: str, srcport: int, dstport: int, payload: bytes) -> Detection:
    """Nhận diện giao thức ứng dụng của một gói TCP hoặc UDP.

    Thứ tự quyết định:
      1. Payload rỗng -> (None, None): gói điều khiển như SYN, ACK không mang dữ liệu ứng dụng.
      2. Tín hiệu payload mạnh -> giao thức đó ("payload+port" nếu port cũng khớp).
      3. Tín hiệu payload yếu và port khớp -> ("SMTP", "payload+port").
      4. Chỉ port khớp -> giao thức theo port, "port".
      5. Còn lại -> ("UNKNOWN", None).
    """
    if not payload:
        return Detection(None, None)

    by_port = _port_protocols(transport, srcport, dstport)

    proto = _strong_match(transport, payload)
    if proto:
        return Detection(proto, "payload+port" if proto in by_port else "payload")

    if SMTP in by_port and any(p.match(payload) for p in _SMTP_WEAK):
        return Detection(SMTP, "payload+port")

    if by_port:
        return Detection(by_port[0], "port")

    return Detection(UNKNOWN, None)
