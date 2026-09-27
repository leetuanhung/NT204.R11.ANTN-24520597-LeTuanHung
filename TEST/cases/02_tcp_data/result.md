# Case 02: TCP data

**Yêu cầu của đề:** Parse TCP packet có payload

**Kết quả: ĐẠT** (9/9 kiểm tra đạt)

## Lệnh chạy

```bash
python main.py --pcap TEST/cases/02_tcp_data/input.pcap --output TEST/cases/02_tcp_data/output.jsonl
```

Đầu vào: `input.pcap` (2 gói). Đầu ra: `output.jsonl` (2 sự kiện).

## Kiểm tra

| Kiểm tra | Mong đợi | Thực tế | Kết quả |
|---|---|---|---|
| Chương trình kết thúc bình thường (mã thoát 0) | `0` | `0` | ĐẠT |
| Không có traceback (không crash) | `False` | `False` | ĐẠT |
| Transport | `'TCP'` | `'TCP'` | ĐẠT |
| Loại gói | `'PSH/ACK'` | `'PSH/ACK'` | ĐẠT |
| Độ dài payload | `27` | `27` | ĐẠT |
| Payload (giải hex) | `'Hello IDS, this is TCP data'` | `'Hello IDS, this is TCP data'` | ĐẠT |
| seq, ack | `(2000, 7000)` | `(2000, 7000)` | ĐẠT |
| Gói trả lời xác nhận đủ 27 byte (ack = 2000 + 27) | `2027` | `2027` | ĐẠT |
| Giao thức ứng dụng (port 9000, dữ liệu lạ) | `'UNKNOWN'` | `'UNKNOWN'` | ĐẠT |

## Màn hình

```
#1 192.168.10.5:51001 -> 93.184.216.34:9000 TCP [PSH/ACK] seq=2000 ack=7000 win=8192 len=27 app=UNKNOWN
#2 93.184.216.34:9000 -> 192.168.10.5:51001 TCP [ACK] seq=7000 ack=2027 win=8192 len=0
Đã xử lý 2 gói, ghi 2 sự kiện vào TEST/cases/02_tcp_data/output.jsonl (malformed: 0, bỏ qua: 0)
```
