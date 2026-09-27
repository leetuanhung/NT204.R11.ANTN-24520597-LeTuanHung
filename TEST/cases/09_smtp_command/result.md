# Case 09: SMTP command

**Yêu cầu của đề:** Parse HELO/EHLO, MAIL FROM hoặc RCPT TO

**Kết quả: ĐẠT** (10/10 kiểm tra đạt)

## Lệnh chạy

```bash
python main.py --pcap TEST/cases/09_smtp_command/input.pcap --output TEST/cases/09_smtp_command/output.jsonl
```

Đầu vào: `input.pcap` (4 gói). Đầu ra: `output.jsonl` (4 sự kiện).

## Kiểm tra

| Kiểm tra | Mong đợi | Thực tế | Kết quả |
|---|---|---|---|
| Chương trình kết thúc bình thường (mã thoát 0) | `0` | `0` | ĐẠT |
| Không có traceback (không crash) | `False` | `False` | ĐẠT |
| Giao thức ứng dụng | `['SMTP', 'SMTP', 'SMTP', 'SMTP']` | `['SMTP', 'SMTP', 'SMTP', 'SMTP']` | ĐẠT |
| Gói 1: lệnh EHLO | `{'command': 'EHLO', 'parameter': 'client.example.com'}` | `{'command': 'EHLO', 'parameter': 'client.example.com'}` | ĐẠT |
| Gói 1: tên máy khai báo | `'client.example.com'` | `'client.example.com'` | ĐẠT |
| Gói 2: lệnh MAIL | `'MAIL'` | `'MAIL'` | ĐẠT |
| Gói 2: người gửi | `'alice@example.com'` | `'alice@example.com'` | ĐẠT |
| Gói 3: lệnh RCPT | `'RCPT'` | `'RCPT'` | ĐẠT |
| Gói 3: người nhận | `['bob@example.org']` | `['bob@example.org']` | ĐẠT |
| Gói 4: lệnh HELO | `{'command': 'HELO', 'parameter': 'old-client'}` | `{'command': 'HELO', 'parameter': 'old-client'}` | ĐẠT |

## Màn hình

```
#1 192.168.10.5:51010 -> 192.168.10.25:25 TCP [PSH/ACK] seq=0 ack=0 win=8192 len=25 app=SMTP(payload+port) EHLO client.example.com
#2 192.168.10.5:51010 -> 192.168.10.25:25 TCP [PSH/ACK] seq=0 ack=0 win=8192 len=41 app=SMTP(payload+port) MAIL FROM:<alice@example.com> SIZE=1024
#3 192.168.10.5:51010 -> 192.168.10.25:25 TCP [PSH/ACK] seq=0 ack=0 win=8192 len=27 app=SMTP(payload+port) RCPT TO:<bob@example.org>
#4 192.168.10.5:51010 -> 192.168.10.25:25 TCP [PSH/ACK] seq=0 ack=0 win=8192 len=17 app=SMTP(payload+port) HELO old-client
Đã xử lý 4 gói, ghi 4 sự kiện vào TEST/cases/09_smtp_command/output.jsonl (malformed: 0, bỏ qua: 0)
```
