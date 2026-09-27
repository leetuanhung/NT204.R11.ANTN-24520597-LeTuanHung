# Case 05: HTTP POST

**Yêu cầu của đề:** Parse HTTP request có body

**Kết quả: ĐẠT** (9/9 kiểm tra đạt)

## Lệnh chạy

```bash
python main.py --pcap TEST/cases/05_http_post/input.pcap --output TEST/cases/05_http_post/output.jsonl
```

Đầu vào: `input.pcap` (1 gói). Đầu ra: `output.jsonl` (1 sự kiện).

## Kiểm tra

| Kiểm tra | Mong đợi | Thực tế | Kết quả |
|---|---|---|---|
| Chương trình kết thúc bình thường (mã thoát 0) | `0` | `0` | ĐẠT |
| Không có traceback (không crash) | `False` | `False` | ĐẠT |
| Method | `'POST'` | `'POST'` | ĐẠT |
| URI | `'/login'` | `'/login'` | ĐẠT |
| Content-Type | `'application/x-www-form-urlencoded'` | `'application/x-www-form-urlencoded'` | ĐẠT |
| Content-Length | `36` | `36` | ĐẠT |
| Body | `'username=student&comment=hello+world'` | `'username=student&comment=hello+world'` | ĐẠT |
| Độ dài body | `36` | `36` | ĐẠT |
| Body đầy đủ trong gói | `True` | `True` | ĐẠT |

## Màn hình

```
#1 192.168.10.5:51004 -> 93.184.216.34:80 TCP [PSH/ACK] seq=0 ack=0 win=8192 len=148 app=HTTP(payload+port) POST http://example.com/login
Đã xử lý 1 gói, ghi 1 sự kiện vào TEST/cases/05_http_post/output.jsonl (malformed: 0, bỏ qua: 0)
```
