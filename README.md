# Packet Capture & Parser cho hệ thống IDS

Bài tập 1 môn Hệ thống tìm kiếm, phát hiện và ngăn chặn xâm nhập (NT204).

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

## Chạy unit test

```bash
python -m unittest discover -v tests
```

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
TEST/                # Kết quả các test case
```

## Sử dụng công cụ AI

| Công cụ | Mục đích | Phần mã nguồn |
|---|---|---|
| Claude Code | Hướng dẫn từng bước, gợi ý kiến trúc và mã nguồn | `ids/capture.py`, `ids/linktypes.py`, `ids/parsers/errors.py`, `ids/parsers/network.py`, `ids/parsers/transport.py`, `ids/detector.py`, `ids/parsers/http.py`, `ids/parsers/dns.py`, `ids/parsers/smtp.py`, `ids/pipeline.py`, `ids/output.py`, `main.py`, các file trong `tests/` |
