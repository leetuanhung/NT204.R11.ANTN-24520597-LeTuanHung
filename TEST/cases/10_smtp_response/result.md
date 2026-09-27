# Case 10: SMTP response

**Yêu cầu của đề:** Parse SMTP status code

**Kết quả: ĐẠT** (8/8 kiểm tra đạt)

## Lệnh chạy

```bash
python main.py --pcap TEST/cases/10_smtp_response/input.pcap --output TEST/cases/10_smtp_response/output.jsonl
```

Đầu vào: `input.pcap` (4 gói). Đầu ra: `output.jsonl` (4 sự kiện).

## Kiểm tra

| Kiểm tra | Mong đợi | Thực tế | Kết quả |
|---|---|---|---|
| Chương trình kết thúc bình thường (mã thoát 0) | `0` | `0` | ĐẠT |
| Không có traceback (không crash) | `False` | `False` | ĐẠT |
| Status code của 4 gói | `[220, 250, 250, 550]` | `[220, 250, 250, 550]` | ĐẠT |
| Gói 1: banner | `'mail.example.com ESMTP Postfix'` | `'mail.example.com ESMTP Postfix'` | ĐẠT |
| Gói 2: phản hồi nhiều dòng | `True` | `True` | ĐẠT |
| Gói 2: tính năng máy chủ | `['PIPELINING', 'SIZE 10240000', 'STARTTLS']` | `['PIPELINING', 'SIZE 10240000', 'STARTTLS']` | ĐẠT |
| Gói 3: mã trạng thái mở rộng | `'2.1.0'` | `'2.1.0'` | ĐẠT |
| Gói 4: mã lỗi và mã mở rộng | `(550, '5.1.1')` | `(550, '5.1.1')` | ĐẠT |

## Màn hình

```
#1 192.168.10.25:25 -> 192.168.10.5:51010 TCP [PSH/ACK] seq=0 ack=0 win=8192 len=36 app=SMTP(payload+port) 220 mail.example.com ESMTP Postfix
#2 192.168.10.25:25 -> 192.168.10.5:51010 TCP [PSH/ACK] seq=0 ack=0 win=8192 len=71 app=SMTP(payload+port) 250 mail.example.com (+3 dòng)
#3 192.168.10.25:25 -> 192.168.10.5:51010 TCP [PSH/ACK] seq=0 ack=0 win=8192 len=14 app=SMTP(payload+port) 250 2.1.0 Ok
#4 192.168.10.25:25 -> 192.168.10.5:51010 TCP [PSH/ACK] seq=0 ack=0 win=8192 len=46 app=SMTP(payload+port) 550 5.1.1 <nobody@example.org>: User unknown
Đã xử lý 4 gói, ghi 4 sự kiện vào TEST/cases/10_smtp_response/output.jsonl (malformed: 0, bỏ qua: 0)
```
