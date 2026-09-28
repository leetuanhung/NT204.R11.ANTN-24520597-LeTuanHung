# Packet Capture & Parser cho hệ thống IDS

Bài tập 1 môn Hệ thống tìm kiếm, phát hiện và ngăn chặn xâm nhập (NT204).

## Tổng quan

Module thu thập gói tin (live hoặc từ file PCAP), phân tích các giao thức và ghi mỗi gói thành một
sự kiện JSON chuẩn hóa. Các module IDS ở bài sau chỉ cần đọc file JSON Lines, không cần Scapy hay
byte thô.

```
Live interface / file PCAP                 (ids/capture.py)
        |  RawPacket: timestamp + byte thô + linktype
        v
Network Parser: Ethernet/VLAN/SLL, IPv4    (ids/parsers/network.py)
        v
Transport Parser: TCP, UDP                 (ids/parsers/transport.py)
        v
Application Protocol Detector              (ids/detector.py)
        v
Application Protocol Parser: HTTP/1.x, DNS, SMTP   (ids/parsers/http.py, dns.py, smtp.py)
        v
Normalized IDS Event -> output/events.jsonl        (ids/pipeline.py, ids/output.py)
```

| Tầng | Giao thức | Ghi chú |
|---|---|---|
| Network | IPv4 | Gói không phải IPv4 (ARP, IPv6...) được đánh dấu `UNKNOWN` |
| Transport | TCP, UDP | TCP có cờ, option và nhãn bắt tay (SYN, SYN/ACK, ACK) |
| Application | HTTP/1.x, DNS, SMTP | DNS qua cả UDP và TCP; nhận diện theo payload trước, port sau |

Điểm chính:

- **Một pipeline duy nhất** cho cả live capture và PCAP.
- **Tự parse byte thô** bằng `struct`; Scapy chỉ dùng để bắt gói và đọc file.
- **Nhận diện giao thức trên port không chuẩn** nhờ kiểm tra nội dung payload (điểm thưởng mục 5).
- **Không dừng với gói hỏng:** mỗi tầng bắt lỗi riêng và giữ phần đã đọc được. Đã thử với hàng triệu
  gói bị làm hỏng ngẫu nhiên (`tests/test_robustness.py`).
- **Không ghi mật khẩu ra log:** thông tin trong `AUTH` của SMTP và header `Authorization` của HTTP
  được che, payload hex của gói đó cũng bị xóa.

## Cài đặt

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Sử dụng

```bash
sudo ./venv/bin/python main.py --interface eth0   # live capture (cần quyền root)
python main.py --pcap test.pcap                    # đọc file PCAP
```

Kết quả được ghi vào `output/events.jsonl`, mỗi dòng là một sự kiện JSON của một gói.

| Tùy chọn | Ý nghĩa |
|---|---|
| `--output`, `-o` | File JSON Lines để ghi (mặc định `output/events.jsonl`) |
| `--append` | Ghi tiếp vào file thay vì ghi đè |
| `--skip-unknown` | Không ghi gói thuộc giao thức không hỗ trợ (gói hỏng vẫn được ghi) |
| `--max-payload` | Số byte payload tối đa ghi dạng hex (mặc định 1024) |
| `--quiet`, `-q` | Không in từng gói ra màn hình |
| `--filter`, `--count` | BPF filter và số gói cần bắt khi live capture |

## Cấu trúc sự kiện

Mọi sự kiện luôn có các trường chung:

```
packet_id, timestamp, time, source, frame_len,
src_ip, dst_ip, src_port, dst_port,
network, transport, app_protocol, app_detected_by,
malformed, truncated, errors
```

Tùy gói, sự kiện có thêm các nhóm theo giao thức: `eth`, `ip`, `tcp`, `udp`, `http`, `dns`, `smtp`.
Tên trường trong mỗi nhóm theo Wireshark display filter, bỏ tiền tố giao thức.
Ví dụ `tcp.flags.syn` là `event["tcp"]["flags"]["syn"]`.

## Test case bắt buộc (mục 9)

Chạy lại toàn bộ, hoặc chỉ một số case:

```bash
python TEST/testcases.py          # tất cả
python TEST/testcases.py 01 12    # chỉ case 01 và 12
```

Mỗi case có thư mục riêng trong `TEST/cases/` gồm `input.pcap` (đầu vào), `output.jsonl` (kết quả
của `main.py`) và `result.md` (so sánh mong đợi với thực tế, kèm màn hình).

| Case | Test | Yêu cầu | Kết quả |
|---|---|---|---|
| 01 | [TCP handshake](TEST/cases/01_tcp_handshake/result.md) | Nhận diện SYN, SYN/ACK, ACK | Đạt |
| 02 | [TCP data](TEST/cases/02_tcp_data/result.md) | Parse TCP packet có payload | Đạt |
| 03 | [UDP](TEST/cases/03_udp/result.md) | Parse UDP packet | Đạt |
| 04 | [HTTP GET](TEST/cases/04_http_get/result.md) | Parse HTTP request | Đạt |
| 05 | [HTTP POST](TEST/cases/05_http_post/result.md) | Parse HTTP request có body | Đạt |
| 06 | [HTTP response](TEST/cases/06_http_response/result.md) | Parse status code và header | Đạt |
| 07 | [DNS Query](TEST/cases/07_dns_query/result.md) | Parse domain và query type | Đạt |
| 08 | [DNS Response](TEST/cases/08_dns_response/result.md) | Parse ít nhất một answer | Đạt |
| 09 | [SMTP command](TEST/cases/09_smtp_command/result.md) | Parse HELO/EHLO, MAIL FROM, RCPT TO | Đạt |
| 10 | [SMTP response](TEST/cases/10_smtp_response/result.md) | Parse SMTP status code | Đạt |
| 11 | [Unknown protocol](TEST/cases/11_unknown_protocol/result.md) | Không crash | Đạt |
| 12 | [Malformed packet](TEST/cases/12_malformed_packet/result.md) | Không crash (kèm gói cuối bị cắt cụt trong file) | Đạt |
| 13 | [HTTP trên port 4444](TEST/cases/13_http_non_standard_port/result.md) | Điểm thưởng mục 5: nhận diện trên port không chuẩn | Đạt |

Kết quả unit test của từng module nằm trong các file `TEST/unit_*.txt`.

## Chạy unit test

```bash
python -m unittest discover -v tests
```

## Giới hạn đã biết

- Mỗi gói được xử lý riêng: không ghép luồng TCP, không ghép mảnh IP. Thông điệp HTTP, DNS qua TCP
  hoặc thư SMTP bị chia qua nhiều gói chỉ được đọc phần nằm trong từng gói.
- Nhận diện giao thức không nhớ trạng thái kết nối. Gói tiếp nối trên port không chuẩn có thể ra
  `UNKNOWN`.
- Không đọc được dữ liệu đã mã hóa: HTTPS, SMTP sau `STARTTLS`, DNS over TLS/HTTPS.
- Chỉ hỗ trợ IPv4 ở tầng mạng; IPv6 được đánh dấu `UNKNOWN`.
- HTTP: chưa giải mã body chunked, gzip, URL encoding. SMTP: chưa giải mã MIME.
- Không kiểm tra checksum TCP/UDP (cần pseudo-header; checksum offload làm sai kết quả khi bắt trên
  máy gửi). Checksum IPv4 có kiểm tra.

## Cấu trúc thư mục

```
main.py              # CLI, chọn chế độ live hoặc pcap
ids/capture.py       # Nguồn packet: live interface hoặc file PCAP -> (timestamp, raw bytes)
ids/linktypes.py     # Mã linktype libpcap
ids/parsers/network.py    # Bỏ header lớp 2, parse IPv4 (tên trường theo Wireshark ip.*)
ids/parsers/transport.py  # Parse TCP, UDP (tên trường theo Wireshark tcp.*, udp.*)
ids/detector.py      # Nhận diện HTTP, DNS, SMTP theo payload và port
ids/parsers/http.py  # Parse HTTP/1.x (tên trường theo Wireshark http.*)
ids/parsers/dns.py   # Parse DNS qua UDP và TCP (tên trường theo Wireshark dns.*)
ids/parsers/smtp.py  # Parse lệnh, phản hồi và nội dung thư SMTP (tên trường theo Wireshark smtp.*)
ids/pipeline.py      # Ghép các tầng thành sự kiện chuẩn hóa
ids/output.py        # Ghi sự kiện ra file JSON Lines
tests/               # Unit test (unittest)
TEST/                # Kết quả unit test, test case (cases/) và script chạy test case
```

## Sử dụng công cụ AI

| Công cụ | Mục đích | Phần mã nguồn |
|---|---|---|
| Claude Code | Hướng dẫn từng bước, thiết kế kiến trúc, viết mã nguồn và test | `ids/`, `main.py`, `tests/`, `TEST/testcases.py` |
