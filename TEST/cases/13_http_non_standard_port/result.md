# Case 13: HTTP trên port không chuẩn (điểm thưởng mục 5)

**Yêu cầu của đề:** Nhận diện đúng application protocol trên non-standard port

**Kết quả: ĐẠT** (6/6 kiểm tra đạt)

## Lệnh chạy

```bash
python main.py --pcap TEST/cases/13_http_non_standard_port/input.pcap --output TEST/cases/13_http_non_standard_port/output.jsonl
```

Đầu vào: `input.pcap` (2 gói). Đầu ra: `output.jsonl` (2 sự kiện).

## Kiểm tra

| Kiểm tra | Mong đợi | Thực tế | Kết quả |
|---|---|---|---|
| Chương trình kết thúc bình thường (mã thoát 0) | `0` | `0` | ĐẠT |
| Không có traceback (không crash) | `False` | `False` | ĐẠT |
| Gói 1: giao thức và cách nhận diện | `('HTTP', 'payload')` | `('HTTP', 'payload')` | ĐẠT |
| Gói 1: port đích | `4444` | `4444` | ĐẠT |
| Gói 1: URL đầy đủ | `'http://c2.example.net/shell?cmd=id'` | `'http://c2.example.net/shell?cmd=id'` | ĐẠT |
| Gói 2: response trên port 4444 | `('HTTP', 'payload', 200)` | `('HTTP', 'payload', 200)` | ĐẠT |

## Màn hình

```
#1 192.168.10.5:51040 -> 93.184.216.34:4444 TCP [PSH/ACK] seq=0 ack=0 win=8192 len=52 app=HTTP(payload) GET http://c2.example.net/shell?cmd=id
#2 93.184.216.34:4444 -> 192.168.10.5:51040 TCP [PSH/ACK] seq=0 ack=0 win=8192 len=40 app=HTTP(payload) 200 OK
Đã xử lý 2 gói, ghi 2 sự kiện vào TEST/cases/13_http_non_standard_port/output.jsonl (malformed: 0, bỏ qua: 0)
```
