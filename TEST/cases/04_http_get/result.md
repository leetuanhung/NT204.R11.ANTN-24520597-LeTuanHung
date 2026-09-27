# Case 04: HTTP GET

**Yêu cầu của đề:** Parse HTTP request

**Kết quả: ĐẠT** (11/11 kiểm tra đạt)

## Lệnh chạy

```bash
python main.py --pcap TEST/cases/04_http_get/input.pcap --output TEST/cases/04_http_get/output.jsonl
```

Đầu vào: `input.pcap` (1 gói). Đầu ra: `output.jsonl` (1 sự kiện).

## Kiểm tra

| Kiểm tra | Mong đợi | Thực tế | Kết quả |
|---|---|---|---|
| Chương trình kết thúc bình thường (mã thoát 0) | `0` | `0` | ĐẠT |
| Không có traceback (không crash) | `False` | `False` | ĐẠT |
| Giao thức ứng dụng | `('HTTP', 'payload+port')` | `('HTTP', 'payload+port')` | ĐẠT |
| Method | `'GET'` | `'GET'` | ĐẠT |
| URI | `'/search?q=ids&lang=vi'` | `'/search?q=ids&lang=vi'` | ĐẠT |
| Version | `'HTTP/1.1'` | `'HTTP/1.1'` | ĐẠT |
| URL đầy đủ | `'http://example.com/search?q=ids&lang=vi'` | `'http://example.com/search?q=ids&lang=vi'` | ĐẠT |
| Host | `'example.com'` | `'example.com'` | ĐẠT |
| User-Agent | `'Mozilla/5.0 (X11; Linux x86_64)'` | `'Mozilla/5.0 (X11; Linux x86_64)'` | ĐẠT |
| Cookie | `'session=abc123'` | `'session=abc123'` | ĐẠT |
| Header đầy đủ | `True` | `True` | ĐẠT |

## Màn hình

```
#1 192.168.10.5:51003 -> 93.184.216.34:80 TCP [PSH/ACK] seq=0 ack=0 win=8192 len=145 app=HTTP(payload+port) GET http://example.com/search?q=ids&lang=vi
Đã xử lý 1 gói, ghi 1 sự kiện vào TEST/cases/04_http_get/output.jsonl (malformed: 0, bỏ qua: 0)
```
