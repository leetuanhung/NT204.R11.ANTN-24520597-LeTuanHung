"""Parsing pipeline: biến một RawPacket thành một sự kiện IDS chuẩn hóa (dict).

    Raw Packet
      -> Network Parser         (parse_link, parse_ipv4)
      -> Transport Parser       (parse_tcp, parse_udp)
      -> App Protocol Detector  (detect_app)
      -> App Protocol Parser    (parse_http, parse_dns, parse_smtp)
      -> Normalized IDS Event   (dict, ghi được thẳng ra JSON)

Detection Engine ở các bài sau chỉ làm việc với dict này, không cần Scapy hay byte thô.
Nguyên tắc: process() KHÔNG BAO GIỜ ném lỗi. Tầng nào lỗi thì ghi vào "errors",
đặt "malformed" = True, và giữ nguyên kết quả của các tầng trước đó.
"""

import logging
from collections import Counter
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ids.detector import detect_app
from ids.parsers.dns import parse_dns
from ids.parsers.errors import ParseError
from ids.parsers.http import parse_http
from ids.parsers.network import ETHERTYPE_IPV4, ETHERTYPE_NAMES, parse_ipv4, parse_link
from ids.parsers.smtp import parse_smtp
from ids.parsers.transport import MAX_PAYLOAD_HEX, parse_tcp, parse_udp

if TYPE_CHECKING:
    # Chỉ dùng để ghi kiểu. Import thật sẽ kéo theo Scapy, trong khi pipeline không cần Scapy.
    from ids.capture import RawPacket

log = logging.getLogger(__name__)

IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

# Tên giao thức ứng dụng -> (tên nhóm trong event, hàm parse nhận (payload, transport))
APP_PARSERS = {
    "HTTP": ("http", lambda payload, transport: parse_http(payload)),
    "DNS":  ("dns", parse_dns),
    "SMTP": ("smtp", lambda payload, transport: parse_smtp(payload)),
}


class Pipeline:
    """Giữ bộ đếm packet_id và thống kê; mỗi gói gọi process() một lần."""

    def __init__(self, skip_unknown: bool = False, max_payload: int = MAX_PAYLOAD_HEX) -> None:
        self.skip_unknown = skip_unknown
        self.max_payload = max_payload
        self.packet_id = 0
        self.stats = Counter()

    # ------------------------------------------------------------------ API
    def process(self, raw: "RawPacket") -> dict | None:
        """Trả về event dict, hoặc None nếu gói bị bỏ qua do skip_unknown."""
        self.packet_id += 1
        event = self._new_event(raw)
        try:
            self._parse_layers(raw, event)
        except Exception as exc:
            # Lưới an toàn cuối cùng: bug trong parser cũng không được làm dừng chương trình
            log.exception("Lỗi không mong đợi ở gói %d", event["packet_id"])
            self._error(event, f"internal: {type(exc).__name__}: {exc}")

        self.stats["total"] += 1
        self.stats["malformed"] += event["malformed"]
        if self.skip_unknown and self._is_unknown(event):
            self.stats["skipped"] += 1
            return None
        self.stats[event["app_protocol"] or event["transport"] or event["network"]] += 1
        return event

    # ------------------------------------------------------------ các tầng
    def _new_event(self, raw: "RawPacket") -> dict:
        return {
            "packet_id": self.packet_id,
            "timestamp": raw.timestamp,
            "time": datetime.fromtimestamp(raw.timestamp, timezone.utc).isoformat(),
            "source": raw.source,
            "frame_len": len(raw.data),
            "src_ip": None, "dst_ip": None, "src_port": None, "dst_port": None,
            "network": None, "transport": None,
            "app_protocol": None, "app_detected_by": None,
            "malformed": False, "truncated": False, "errors": [],
        }

    def _parse_layers(self, raw: "RawPacket", event: dict) -> None:
        # Tầng 2: bỏ header lớp 2
        try:
            eth, ethertype, l3 = parse_link(raw.data, raw.linktype)
        except ParseError as exc:
            self._error(event, str(exc))
            event["network"] = "UNKNOWN"
            return
        if eth:
            event["eth"] = eth
        if ethertype != ETHERTYPE_IPV4:
            # ARP, IPv6, LLDP...: không thuộc giao thức hỗ trợ, đánh dấu UNKNOWN (mục 3 của đề)
            event["network"] = "UNKNOWN"
            event["ethertype"] = ethertype
            event["ethertype_name"] = ETHERTYPE_NAMES.get(ethertype, f"0x{ethertype:04x}")
            return

        # Tầng 3: IPv4
        event["network"] = "IPv4"
        try:
            ip, l4 = parse_ipv4(l3)
        except ParseError as exc:
            self._error(event, str(exc))
            return
        event["ip"] = ip
        event["src_ip"], event["dst_ip"] = ip["src"], ip["dst"]
        event["truncated"] = ip["truncated"]
        if ip["frag_offset"] > 0:
            # Mảnh sau của gói bị phân mảnh: không có header tầng 4 để đọc
            event["transport"] = "FRAGMENT"
            return

        # Tầng 4: TCP hoặc UDP
        if ip["proto"] == IP_PROTO_TCP:
            transport, parser = "TCP", parse_tcp
        elif ip["proto"] == IP_PROTO_UDP:
            transport, parser = "UDP", parse_udp
        else:
            event["transport"] = ip["proto_name"]      # ICMP, GRE...: không parse sâu hơn
            return
        event["transport"] = transport
        try:
            l4_fields, payload = parser(l4, self.max_payload)
        except ParseError as exc:
            self._error(event, str(exc))
            return
        event[transport.lower()] = l4_fields
        event["src_port"], event["dst_port"] = l4_fields["srcport"], l4_fields["dstport"]
        event["truncated"] = event["truncated"] or l4_fields.get("truncated", False)

        # Nhận diện và parse tầng ứng dụng
        protocol, detected_by = detect_app(transport, event["src_port"], event["dst_port"], payload)
        event["app_protocol"], event["app_detected_by"] = protocol, detected_by
        if protocol not in APP_PARSERS:
            return                                      # None (không payload) hoặc UNKNOWN
        group, parse = APP_PARSERS[protocol]
        try:
            app = parse(payload, transport)
        except ParseError as exc:
            self._error(event, str(exc))
            return
        event[group] = app
        if self._carries_credentials(app):
            # Parser ứng dụng đã che mật khẩu, nhưng payload hex ở tầng transport vẫn chứa nguyên
            # văn. Xóa luôn phần đó, nếu không mật khẩu vẫn lộ trong file log (chỉ là ở dạng hex).
            l4_fields["payload"] = ""
            l4_fields["payload_redacted"] = True
        if app.get("malformed") is True:                # DNS đánh dấu hỏng nhưng vẫn giữ phần đã đọc
            self._error(event, f"DNS: {app.get('error')}")

    # ------------------------------------------------------------- tiện ích
    @staticmethod
    def _error(event: dict, message: str) -> None:
        event["malformed"] = True
        event["errors"].append(message)

    @staticmethod
    def _carries_credentials(app: dict) -> bool:
        """HTTP có header Authorization, SMTP có lệnh AUTH hoặc dòng dữ liệu AUTH LOGIN."""
        return "auth" in app or app.get("type") == "auth_data"

    @staticmethod
    def _is_unknown(event: dict) -> bool:
        """Gói không thuộc giao thức hỗ trợ. Gói hỏng luôn được giữ vì IDS cần thấy chúng."""
        if event["malformed"]:
            return False
        return (event["network"] == "UNKNOWN"
                or event["transport"] not in ("TCP", "UDP")
                or event["app_protocol"] == "UNKNOWN")
