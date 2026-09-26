"""SMTP parser: tách lệnh của client, phản hồi của server và nội dung thư.

Tên trường theo Wireshark display filter (https://www.wireshark.org/docs/dfref/s/smtp.html),
bỏ tiền tố "smtp." và đặt trong nhóm "smtp". Ví dụ smtp.req.command -> smtp["req"]["command"],
smtp.response.code -> smtp["response"]["code"].

SMTP là giao thức dạng dòng chữ (RFC 5321): mỗi lệnh hoặc phản hồi kết thúc bằng CRLF.
Một gói có thể chứa nhiều dòng (ví dụ client gửi liền MAIL FROM, RCPT TO nhờ PIPELINING,
hoặc server trả lời EHLO bằng nhiều dòng "250-...").
"""

import base64
import binascii
import re

from ids.parsers.errors import ParseError

MAX_LINES = 100             # Số lệnh/dòng phản hồi tối đa ghi vào kết quả
MAX_MESSAGE_TEXT = 1024     # Số ký tự nội dung thư tối đa ghi vào kết quả

# Lệnh SMTP (RFC 5321 và các mở rộng phổ biến). Không phân biệt hoa thường.
COMMANDS = {"HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET", "VRFY", "EXPN", "HELP", "NOOP",
            "QUIT", "AUTH", "STARTTLS", "BDAT", "ETRN", "TURN", "ATRN"}

# Dòng phản hồi: 3 chữ số, rồi dấu cách (dòng cuối) hoặc dấu gạch (còn dòng sau), rồi nội dung
_RESPONSE_LINE = re.compile(r"([2-5][0-5][0-9])([ -]|$)(.*)")
# Mã trạng thái mở rộng (RFC 3463) ở đầu nội dung, ví dụ "250 2.1.0 Ok"
_ENHANCED = re.compile(r"([245]\.\d{1,3}\.\d{1,3})(?: |$)")
# Địa chỉ trong MAIL FROM:<a@b> và RCPT TO:<a@b>; chấp nhận cả dạng thiếu dấu <> của client viết ẩu
_PATH = re.compile(r"(FROM|TO):\s*(?:<([^>]*)>|(\S+))(.*)", re.IGNORECASE)
# Một dòng base64 đứng riêng: gần như chắc chắn là tên đăng nhập hoặc mật khẩu của AUTH LOGIN
_BASE64_LINE = re.compile(r"[A-Za-z0-9+/]{4,512}={0,2}")
# Header của thư (RFC 5322) cần cho IDS, ví dụ phát hiện phishing
_MAIL_HEADERS = {"from", "to", "subject", "date", "message-id", "reply-to"}


def _decode(b: bytes) -> str:
    """SMTP chủ yếu là ASCII; SMTPUTF8 cho phép UTF-8 trong địa chỉ. Byte lạ được thay thế."""
    return b.decode("utf-8", errors="replace")


def _split_lines(payload: bytes) -> tuple[list[str], bool]:
    """Tách thành các dòng. Trả về (dòng, dòng_cuối_chưa_kết_thúc).

    Chấp nhận cả CRLF chuẩn và LF đơn. Nếu payload không kết thúc bằng xuống dòng thì dòng cuối
    bị cắt giữa chừng (lệnh bị chia qua hai gói TCP).
    """
    incomplete = not payload.endswith(b"\n")
    lines = [_decode(line.rstrip(b"\r")) for line in payload.split(b"\n")]
    if not incomplete:
        lines.pop()                       # Phần tử rỗng sau dấu xuống dòng cuối cùng
    return lines, incomplete


def _first_word(line: str) -> str:
    return line.split(" ", 1)[0].upper()


def _parse_auth(parameter: str) -> tuple[dict, str]:
    """Đọc lệnh AUTH. Trả về (thông tin auth, tham số đã che mật khẩu).

    AUTH PLAIN <base64("authzid\\0username\\0password")>
    AUTH LOGIN [<base64(username)>]
    Mật khẩu KHÔNG được ghi ra: IDS chỉ cần biết có thông tin đăng nhập gửi dạng rõ,
    còn file log không được trở thành nơi lưu mật khẩu của người dùng.
    """
    parts = parameter.split()
    mechanism = parts[0].upper() if parts else ""
    auth = {"mechanism": mechanism}
    masked = parameter
    if len(parts) >= 2 and parts[1] != "=":
        masked = f"{parts[0]} ***"        # Che phần dữ liệu đăng nhập ban đầu
        try:
            raw = base64.b64decode(parts[1], validate=True)
        except (binascii.Error, ValueError):
            auth["decode_error"] = True
            return auth, masked
        if mechanism == "PLAIN":
            fields = raw.split(b"\x00")
            if len(fields) == 3:
                auth["username"] = _decode(fields[1])
                auth["password_present"] = bool(fields[2])
            else:
                auth["decode_error"] = True
        elif mechanism == "LOGIN":
            auth["username"] = _decode(raw)
    return auth, masked


def _parse_message(lines: list[str], max_text: int) -> dict:
    """Nội dung thư sau lệnh DATA. Lấy vài header quan trọng nếu có."""
    data = {"lines": len(lines), "end_of_data": "." in lines}
    body_lines = lines[:lines.index(".")] if "." in lines else lines
    headers = {}
    for line in body_lines:
        if not line:
            break                         # Dòng trống: hết phần header của thư
        name, sep, value = line.partition(":")
        key = name.strip().lower()
        if sep and key in _MAIL_HEADERS and key not in headers:
            headers[key] = value.strip()
    if headers:
        data["headers"] = headers
    text = "\n".join(body_lines)
    data["message"] = text[:max_text]
    data["message_truncated"] = len(text) > max_text
    return data


def _parse_requests(lines: list[str], smtp: dict, max_text: int) -> None:
    commands = []
    rcpt_to = []
    unknown = 0
    for i, line in enumerate(lines):
        command = _first_word(line)
        if command not in COMMANDS:
            unknown += 1                  # Ví dụ tên đăng nhập base64 gửi riêng một dòng
            continue
        parameter = line[len(command):].strip()
        if command == "AUTH":
            smtp["auth"], parameter = _parse_auth(parameter)
            line = f"AUTH {parameter}".rstrip()
        elif command in ("HELO", "EHLO"):
            smtp["helo"] = parameter
        elif command in ("MAIL", "RCPT"):
            m = _PATH.match(parameter)
            if m:
                address = m.group(2) if m.group(2) is not None else m.group(3)
                if command == "MAIL":
                    smtp["mail_from"] = address      # "" là người gửi rỗng (thư báo lỗi)
                else:
                    rcpt_to.append(address)
            else:
                unknown += 1              # Thiếu "FROM:" / "TO:"
        if len(commands) < MAX_LINES:
            commands.append({"command": command, "parameter": parameter, "line": line})
        if command == "DATA" and i + 1 < len(lines):
            # Client gửi luôn nội dung thư sau DATA trong cùng gói
            smtp["data"] = _parse_message(lines[i + 1:], max_text)
            break

    if rcpt_to:
        smtp["rcpt_to"] = rcpt_to
    first = commands[0]
    smtp["req"] = {"command": first["command"], "parameter": first["parameter"]}
    smtp["command_line"] = first["line"]
    smtp["commands"] = commands
    smtp["unknown_lines"] = unknown


def _parse_responses(lines: list[str], smtp: dict) -> None:
    parsed = []
    malformed = 0
    code = None
    for line in lines:
        m = _RESPONSE_LINE.fullmatch(line)
        if not m or (code is not None and int(m.group(1)) != code):
            malformed += 1                # Không đúng dạng, hoặc mã khác với dòng đầu
            continue
        code = int(m.group(1))
        parsed.append((m.group(2), m.group(3)))

    texts = [text for _, text in parsed][:MAX_LINES]
    response = {
        "code": code,
        "parameter": texts[0],
        "lines": texts,
        "multiline": len(parsed) > 1,
        # Dòng cuối của phản hồi nhiều dòng dùng dấu cách; dấu gạch nghĩa là còn dòng ở gói sau
        "complete": parsed[-1][0] != "-",
    }
    if m := _ENHANCED.match(texts[0]):
        response["enhanced_status"] = m.group(1)
    if code == 250 and len(parsed) > 1:
        # Trả lời EHLO: dòng đầu là tên máy chủ, các dòng sau là tính năng hỗ trợ
        response["extensions"] = [t.upper() for t in texts[1:]]
    smtp["response"] = response
    smtp["malformed_lines"] = malformed


def parse_smtp(payload: bytes, max_text: int = MAX_MESSAGE_TEXT) -> dict:
    """Parse payload SMTP của một gói.

    Trường "type" cho biết loại nội dung:
      "request"   gói bắt đầu bằng một lệnh của client
      "response"  gói bắt đầu bằng mã phản hồi 3 chữ số của server
      "auth_data" một dòng base64 đứng riêng: tên đăng nhập hoặc mật khẩu của AUTH LOGIN.
                  Chỉ ghi độ dài, không ghi nội dung, để mật khẩu không lọt vào file log.
      "data"      còn lại: nội dung thư sau DATA, hoặc dòng tiếp nối
    """
    if not payload:
        raise ParseError("SMTP: payload rỗng")

    lines, incomplete = _split_lines(payload)
    smtp: dict = {"line_count": len(lines), "incomplete_line": incomplete}

    if _RESPONSE_LINE.fullmatch(lines[0]):
        smtp["type"] = "response"
        _parse_responses(lines, smtp)
    elif _first_word(lines[0]) in COMMANDS:
        smtp["type"] = "request"
        _parse_requests(lines, smtp, max_text)
    elif len(lines) == 1 and _BASE64_LINE.fullmatch(lines[0]) and len(lines[0]) % 4 == 0:
        smtp["type"] = "auth_data"
        smtp["auth_data"] = {"len": len(lines[0])}
    else:
        smtp["type"] = "data"
        smtp["data"] = _parse_message(lines, max_text)
    return smtp
