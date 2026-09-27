# Case 01: TCP handshake

**Yêu cầu của đề:** Nhận diện SYN, SYN/ACK, ACK

**Kết quả: ĐẠT** (12/12 kiểm tra đạt)

## Lệnh chạy

```bash
python main.py --pcap TEST/cases/01_tcp_handshake/input.pcap --output TEST/cases/01_tcp_handshake/output.jsonl
```

Đầu vào: `input.pcap` (3 gói). Đầu ra: `output.jsonl` (3 sự kiện).

## Kiểm tra

| Kiểm tra | Mong đợi | Thực tế | Kết quả |
|---|---|---|---|
| Chương trình kết thúc bình thường (mã thoát 0) | `0` | `0` | ĐẠT |
| Không có traceback (không crash) | `False` | `False` | ĐẠT |
| Số sự kiện | `3` | `3` | ĐẠT |
| Gói 1: loại gói | `'SYN'` | `'SYN'` | ĐẠT |
| Gói 1: cờ SYN bật, ACK tắt | `(True, False)` | `(True, False)` | ĐẠT |
| Gói 2: loại gói | `'SYN/ACK'` | `'SYN/ACK'` | ĐẠT |
| Gói 2: cờ SYN và ACK cùng bật | `(True, True)` | `(True, True)` | ĐẠT |
| Gói 2: ack = seq của gói 1 + 1 | `1001` | `1001` | ĐẠT |
| Gói 3: loại gói | `'ACK'` | `'ACK'` | ĐẠT |
| Gói 3: ack = seq của gói 2 + 1 | `5001` | `5001` | ĐẠT |
| Chiều gói 1: IP và port | `('192.168.10.5', 51000, '93.184.216.34', 80)` | `('192.168.10.5', 51000, '93.184.216.34', 80)` | ĐẠT |
| Gói bắt tay không có tầng ứng dụng | `[None, None, None]` | `[None, None, None]` | ĐẠT |

## Màn hình

```
#1 192.168.10.5:51000 -> 93.184.216.34:80 TCP [SYN] seq=1000 ack=0 win=8192 len=0
#2 93.184.216.34:80 -> 192.168.10.5:51000 TCP [SYN/ACK] seq=5000 ack=1001 win=8192 len=0
#3 192.168.10.5:51000 -> 93.184.216.34:80 TCP [ACK] seq=1001 ack=5001 win=8192 len=0
Đã xử lý 3 gói, ghi 3 sự kiện vào TEST/cases/01_tcp_handshake/output.jsonl (malformed: 0, bỏ qua: 0)
```
