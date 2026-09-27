# Case 07: DNS Query

**Yêu cầu của đề:** Parse domain và query type

**Kết quả: ĐẠT** (9/9 kiểm tra đạt)

## Lệnh chạy

```bash
python main.py --pcap TEST/cases/07_dns_query/input.pcap --output TEST/cases/07_dns_query/output.jsonl
```

Đầu vào: `input.pcap` (2 gói). Đầu ra: `output.jsonl` (2 sự kiện).

## Kiểm tra

| Kiểm tra | Mong đợi | Thực tế | Kết quả |
|---|---|---|---|
| Chương trình kết thúc bình thường (mã thoát 0) | `0` | `0` | ĐẠT |
| Không có traceback (không crash) | `False` | `False` | ĐẠT |
| Giao thức ứng dụng | `('DNS', 'payload+port')` | `('DNS', 'payload+port')` | ĐẠT |
| Gói 1: là câu hỏi (QR = 0) | `False` | `False` | ĐẠT |
| Gói 1: transaction id | `6699` | `6699` | ĐẠT |
| Gói 1: domain | `'www.example.com'` | `'www.example.com'` | ĐẠT |
| Gói 1: query type | `('A', 1)` | `('A', 1)` | ĐẠT |
| Gói 1: class | `'IN'` | `'IN'` | ĐẠT |
| Gói 2: domain và query type | `('example.com', 'MX')` | `('example.com', 'MX')` | ĐẠT |

## Màn hình

```
#1 192.168.10.5:53001 -> 8.8.8.8:53 UDP len=33 app=DNS(payload+port) query A www.example.com
#2 192.168.10.5:53002 -> 8.8.8.8:53 UDP len=29 app=DNS(payload+port) query MX example.com
Đã xử lý 2 gói, ghi 2 sự kiện vào TEST/cases/07_dns_query/output.jsonl (malformed: 0, bỏ qua: 0)
```
