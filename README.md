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
tests/               # Unit test (unittest)
TEST/                # Kết quả các test case
```

## Sử dụng công cụ AI

| Công cụ | Mục đích | Phần mã nguồn |
|---|---|---|
| Claude Code | Hướng dẫn từng bước, gợi ý kiến trúc và mã nguồn | `ids/capture.py`, `ids/linktypes.py`, `ids/parsers/errors.py`, `ids/parsers/network.py`, `ids/parsers/transport.py`, `main.py`, các file trong `tests/` |
