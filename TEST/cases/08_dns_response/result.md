# Case 08: DNS Response

**Yêu cầu của đề:** Parse ít nhất một answer

**Kết quả: ĐẠT** (10/10 kiểm tra đạt)

## Lệnh chạy

```bash
python main.py --pcap TEST/cases/08_dns_response/input.pcap --output TEST/cases/08_dns_response/output.jsonl
```

Đầu vào: `input.pcap` (1 gói). Đầu ra: `output.jsonl` (1 sự kiện).

## Kiểm tra

| Kiểm tra | Mong đợi | Thực tế | Kết quả |
|---|---|---|---|
| Chương trình kết thúc bình thường (mã thoát 0) | `0` | `0` | ĐẠT |
| Không có traceback (không crash) | `False` | `False` | ĐẠT |
| Là câu trả lời (QR = 1) | `True` | `True` | ĐẠT |
| Mã trả lời | `'NOERROR'` | `'NOERROR'` | ĐẠT |
| Số answer khai báo | `2` | `2` | ĐẠT |
| Số answer đọc được | `2` | `2` | ĐẠT |
| Answer 1: CNAME | `('www.example.com', 'CNAME', 'example.com', 300)` | `('www.example.com', 'CNAME', 'example.com', 300)` | ĐẠT |
| Answer 2: A | `('example.com', 'A', '93.184.216.34', 60)` | `('example.com', 'A', '93.184.216.34', 60)` | ĐẠT |
| Gói có dùng nén tên (con trỏ 0xC0) | `True` | `True` | ĐẠT |
| Không bị đánh dấu hỏng | `False` | `False` | ĐẠT |

## Màn hình

```
#1 8.8.8.8:53 -> 192.168.10.5:53001 UDP len=63 app=DNS(payload+port) response NOERROR A www.example.com -> example.com, 93.184.216.34
Đã xử lý 1 gói, ghi 1 sự kiện vào TEST/cases/08_dns_response/output.jsonl (malformed: 0, bỏ qua: 0)
```
