# Case 03: UDP

**Yêu cầu của đề:** Parse UDP packet

**Kết quả: ĐẠT** (9/9 kiểm tra đạt)

## Lệnh chạy

```bash
python main.py --pcap TEST/cases/03_udp/input.pcap --output TEST/cases/03_udp/output.jsonl
```

Đầu vào: `input.pcap` (1 gói). Đầu ra: `output.jsonl` (1 sự kiện).

## Kiểm tra

| Kiểm tra | Mong đợi | Thực tế | Kết quả |
|---|---|---|---|
| Chương trình kết thúc bình thường (mã thoát 0) | `0` | `0` | ĐẠT |
| Không có traceback (không crash) | `False` | `False` | ĐẠT |
| Transport | `'UDP'` | `'UDP'` | ĐẠT |
| Port nguồn, đích | `(51002, 9999)` | `(51002, 9999)` | ĐẠT |
| Trường length (8 byte header + payload) | `54` | `54` | ĐẠT |
| Độ dài payload | `46` | `46` | ĐẠT |
| Payload (giải hex) | `'<14>Sep 26 12:20:00 host app: udp test message'` | `'<14>Sep 26 12:20:00 host app: udp test message'` | ĐẠT |
| Checksum có giá trị (khác 0) | `False` | `False` | ĐẠT |
| Không bị đánh dấu hỏng | `False` | `False` | ĐẠT |

## Màn hình

```
#1 192.168.10.5:51002 -> 93.184.216.34:9999 UDP len=46 app=UNKNOWN
Đã xử lý 1 gói, ghi 1 sự kiện vào TEST/cases/03_udp/output.jsonl (malformed: 0, bỏ qua: 0)
```
