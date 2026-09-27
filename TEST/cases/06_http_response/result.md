# Case 06: HTTP response

**Yêu cầu của đề:** Parse status code và header

**Kết quả: ĐẠT** (10/10 kiểm tra đạt)

## Lệnh chạy

```bash
python main.py --pcap TEST/cases/06_http_response/input.pcap --output TEST/cases/06_http_response/output.jsonl
```

Đầu vào: `input.pcap` (2 gói). Đầu ra: `output.jsonl` (2 sự kiện).

## Kiểm tra

| Kiểm tra | Mong đợi | Thực tế | Kết quả |
|---|---|---|---|
| Chương trình kết thúc bình thường (mã thoát 0) | `0` | `0` | ĐẠT |
| Không có traceback (không crash) | `False` | `False` | ĐẠT |
| Gói 1: status code | `200` | `200` | ĐẠT |
| Gói 1: phrase | `'OK'` | `'OK'` | ĐẠT |
| Gói 1: Server | `'nginx/1.24.0'` | `'nginx/1.24.0'` | ĐẠT |
| Gói 1: Content-Type | `'text/html; charset=utf-8'` | `'text/html; charset=utf-8'` | ĐẠT |
| Gói 1: Set-Cookie | `['sid=xyz; HttpOnly']` | `['sid=xyz; HttpOnly']` | ĐẠT |
| Gói 1: số header | `4` | `4` | ĐẠT |
| Gói 1: body | `'<h1>Hello</h1>'` | `'<h1>Hello</h1>'` | ĐẠT |
| Gói 2: status code và phrase | `(404, 'Not Found')` | `(404, 'Not Found')` | ĐẠT |

## Màn hình

```
#1 93.184.216.34:80 -> 192.168.10.5:51005 TCP [PSH/ACK] seq=0 ack=0 win=8192 len=146 app=HTTP(payload+port) 200 OK
#2 93.184.216.34:80 -> 192.168.10.5:51006 TCP [PSH/ACK] seq=0 ack=0 win=8192 len=67 app=HTTP(payload+port) 404 Not Found
Đã xử lý 2 gói, ghi 2 sự kiện vào TEST/cases/06_http_response/output.jsonl (malformed: 0, bỏ qua: 0)
```
