"""HTTP/1.x parser: tách dòng đầu, header và body từ payload của một gói TCP.

Tên trường theo Wireshark display filter (https://www.wireshark.org/docs/dfref/h/http.html),
bỏ tiền tố "http." và đặt trong nhóm "http". Ví dụ http.request.method -> http["request"]["method"].

Parser làm việc trên TỪNG GÓI, không ghép luồng TCP. Vì vậy một thông điệp HTTP dài
có thể chỉ được thấy một phần; các trường header_complete và body_complete cho biết điều đó.
"""

import base64
import binascii
import re

from ids.parsers.errors import ParseError

MAX_BODY_TEXT = 1024        # Số ký tự body tối đa ghi vào file_data

# Dòng đầu của request và response (RFC 9112). Method phân biệt hoa thường.
_REQUEST_LINE = re.compile(
    rb"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) (\S+) (HTTP/1\.[01])\r?$")
_STATUS_LINE = re.compile(rb"(HTTP/1\.[01]) ([1-5]\d\d)(?: (.*))?\r?$")

# Content-Length chỉ gồm chữ số ASCII. Không dùng str.isdigit() vì nó coi cả "³", "١" là chữ số.
_DIGITS = re.compile(r"[0-9]+")

# Tên header hợp lệ là một "token" (RFC 9110 mục 5.1)
_HEADER_NAME = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")

# Header -> tên trường Wireshark tương ứng (http.host, http.user_agent, ...)
WIRESHARK_HEADERS = {
    "host": "host",
    "user-agent": "user_agent",
    "accept": "accept",
    "content-type": "content_type",
    "cookie": "cookie",
    "referer": "referer",
    "authorization": "authorization",
    "server": "server",
    "location": "location",
    "connection": "connection",
    "transfer-encoding": "transfer_encoding",
    "x-forwarded-for": "x_forwarded_for",
}


def _text(b: bytes) -> str:
    """Header HTTP là byte, không bắt buộc UTF-8. latin-1 ánh xạ 1 byte thành 1 ký tự
    nên không bao giờ lỗi giải mã và không làm mất byte nào."""
    return b.decode("latin-1")


def _split_head(payload: bytes) -> tuple[bytes, bytes, bool]:
    """Tách phần đầu (dòng đầu + header) và body tại dòng trống đầu tiên.

    Chấp nhận cả CRLF CRLF chuẩn lẫn LF LF (một số client viết tay chỉ dùng LF).
    Trả về (head, body, header_complete).
    """
    for sep in (b"\r\n\r\n", b"\n\n"):
        pos = payload.find(sep)
        if pos != -1:
            return payload[:pos], payload[pos + len(sep):], True
    return payload, b"", False            # Chưa thấy dòng trống: header bị cắt giữa chừng


def _parse_content_length(values: list[str]) -> tuple[int | None, bool]:
    """Trả về (content_length, invalid).

    Không hợp lệ khi không phải số không âm, hoặc có nhiều giá trị khác nhau.
    Nhiều Content-Length mâu thuẫn là dấu hiệu kinh điển của HTTP request smuggling.
    """
    distinct = {v.strip() for v in values}
    if len(distinct) != 1:
        return None, True
    value = distinct.pop()
    if not _DIGITS.fullmatch(value):
        return None, True
    return int(value), False


def _mask_authorization(value: str) -> tuple[str, dict]:
    """Che thông tin đăng nhập trong header Authorization / Proxy-Authorization.

    "Basic base64(user:pass)" -> giữ tên đăng nhập, bỏ mật khẩu. Kiểu khác (Bearer, Digest...)
    chỉ giữ tên kiểu. File log của IDS không được trở thành nơi lưu mật khẩu hay token.
    """
    scheme, _, credentials = value.partition(" ")
    auth = {"scheme": scheme}
    if scheme.lower() == "basic" and credentials:
        try:
            decoded = base64.b64decode(credentials.strip(), validate=True).decode("utf-8", "replace")
            username, sep, password = decoded.partition(":")
            auth["username"] = username
            auth["password_present"] = bool(sep and password)
        except (binascii.Error, ValueError):
            auth["decode_error"] = True
    return (f"{scheme} ***" if credentials else scheme), auth


def parse_http(payload: bytes, max_body: int = MAX_BODY_TEXT) -> dict:
    """Parse payload HTTP/1.x của một gói.

    Kết quả có trường "type":
      "request"      dòng đầu là request line
      "response"     dòng đầu là status line
      "continuation" payload không bắt đầu bằng dòng đầu HTTP, thường là phần tiếp theo
                     của body ở gói trước. Không coi là lỗi vì parser không ghép luồng TCP.
    """
    if not payload:
        raise ParseError("HTTP: payload rỗng")

    head, body, header_complete = _split_head(payload)
    lines = head.split(b"\n")
    first = lines[0].rstrip(b"\r")

    http: dict = {}
    if m := _REQUEST_LINE.match(first):
        http["type"] = "request"
        http["request"] = {
            "method": _text(m.group(1)),
            "uri": _text(m.group(2)),
            "version": _text(m.group(3)),
        }
    elif m := _STATUS_LINE.match(first):
        http["type"] = "response"
        http["response"] = {
            "version": _text(m.group(1)),
            "code": int(m.group(2)),
            "phrase": _text(m.group(3) or b""),   # RFC 9112 cho phép phrase rỗng
        }
    else:
        return {"type": "continuation", "len": len(payload)}

    http["line"] = _text(first)

    # ---- Header: "Tên: giá trị", tên không phân biệt hoa thường ----
    headers: dict[str, str] = {}
    raw_values: dict[str, list[str]] = {}
    malformed_lines = 0
    last_name = None
    for raw_line in lines[1:]:
        line = raw_line.rstrip(b"\r")
        if not line:
            continue
        if line[:1] in (b" ", b"\t"):
            # Dòng bắt đầu bằng khoảng trắng là phần nối tiếp của header trước (obs-fold,
            # RFC 9112 mục 5.2). Đã lỗi thời nhưng hay được dùng để né bộ lọc.
            if last_name is None:
                malformed_lines += 1
                continue
            headers[last_name] += " " + _text(line.strip())
            raw_values[last_name][-1] = headers[last_name]
            continue
        name, sep, value = line.partition(b":")
        if not sep or not _HEADER_NAME.fullmatch(name):
            malformed_lines += 1          # Thiếu dấu ":" hoặc tên chứa ký tự lạ
            last_name = None
            continue
        key = _text(name).lower()
        val = _text(value.strip())
        raw_values.setdefault(key, []).append(val)
        # Header trùng tên được nối bằng dấu phẩy (RFC 9110 mục 5.3)
        headers[key] = f"{headers[key]}, {val}" if key in headers else val
        last_name = key

    for header in ("authorization", "proxy-authorization"):
        if header in headers:
            headers[header], auth = _mask_authorization(headers[header])
            http.setdefault("auth", auth)
    http["headers"] = headers
    http["header_complete"] = header_complete
    http["malformed_lines"] = malformed_lines

    for header, field in WIRESHARK_HEADERS.items():
        if header in headers:
            http[field] = headers[header]
    if "set-cookie" in raw_values:
        # Set-Cookie không được nối bằng dấu phẩy vì giá trị cookie có thể chứa dấu phẩy
        http["set_cookie"] = raw_values["set-cookie"]

    if "request" in http and "host" in http:
        uri = http["request"]["uri"]
        # URI dạng tuyệt đối (qua proxy) thì giữ nguyên, còn lại ghép với Host như Wireshark
        http["request"]["full_uri"] = uri if "://" in uri else f"http://{http['host']}{uri}"

    # ---- Body ----
    content_length = None
    if "content-length" in raw_values:
        content_length, invalid = _parse_content_length(raw_values["content-length"])
        http["content_length"] = content_length
        http["content_length_invalid"] = invalid

    # Độ dài body theo RFC 9112 mục 6.3, xét theo thứ tự ưu tiên:
    chunked = "chunked" in headers.get("transfer-encoding", "").lower()
    if chunked and content_length is not None:
        # Có cả hai header: Transfer-Encoding thắng. Đây là kiểu request smuggling CL.TE/TE.CL
        http["cl_te_conflict"] = True

    if not header_complete:
        complete = False                  # Header còn chưa hết thì body chắc chắn chưa đủ
    elif chunked:
        complete = body.endswith(b"0\r\n\r\n")   # Chunk cuối có kích thước 0
    elif content_length is not None:
        complete = len(body) >= content_length
        body = body[:content_length]      # Byte thừa phía sau thuộc thông điệp kế tiếp
    elif http["type"] == "request":
        complete = True                   # Request không khai báo độ dài thì không có body
    else:
        complete = None                   # Response đọc đến khi đóng kết nối: không biết được

    http["chunked"] = chunked
    http["body_len"] = len(body)
    http["body_complete"] = complete
    if body:
        # Body có thể là nhị phân (ảnh, file nén): thay byte không phải UTF-8 bằng ký tự thay thế
        http["file_data"] = body[:max_body].decode("utf-8", errors="replace")
        http["file_data_truncated"] = len(body) > max_body
    return http
