# Case 12: Malformed packet

**Yêu cầu của đề:** Không crash

**Kết quả: ĐẠT** (12/12 kiểm tra đạt)

## Lệnh chạy

```bash
python main.py --pcap TEST/cases/12_malformed_packet/input.pcap --output TEST/cases/12_malformed_packet/output.jsonl
```

Đầu vào: `input.pcap` (9 gói, cắt bớt 10 byte cuối file). Đầu ra: `output.jsonl` (9 sự kiện).

## Kiểm tra

| Kiểm tra | Mong đợi | Thực tế | Kết quả |
|---|---|---|---|
| Chương trình kết thúc bình thường (mã thoát 0) | `0` | `0` | ĐẠT |
| Không có traceback (không crash) | `False` | `False` | ĐẠT |
| Số sự kiện (gói cuối bị cắt vẫn được xử lý) | `9` | `9` | ĐẠT |
| Gói 1-7 bị đánh dấu malformed | `[True, True, True, True, True, True, True]` | `[True, True, True, True, True, True, True]` | ĐẠT |
| Gói 1: lỗi Ethernet | `True` | `True` | ĐẠT |
| Gói 2, 3: lỗi IPv4 | `[True, True]` | `[True, True]` | ĐẠT |
| Gói 4: lỗi TCP, vẫn giữ IP nguồn | `(True, '192.168.10.5')` | `(True, '192.168.10.5')` | ĐẠT |
| Gói 5: lỗi UDP | `True` | `True` | ĐẠT |
| Gói 6: DNS vòng lặp con trỏ, giữ nhóm dns | `(True, True)` | `(True, True)` | ĐẠT |
| Gói 7: DNS thiếu header, vẫn giữ nhóm udp | `(True, True)` | `(True, True)` | ĐẠT |
| Gói 8: byte không decode được, không hỏng, Host đọc được | `(False, 3)` | `(False, 3)` | ĐẠT |
| Gói 9 (bị cắt trong file): vẫn có sự kiện | `9` | `9` | ĐẠT |

## Màn hình

```
#1 MALFORMED Ethernet: cần ít nhất 14 byte, chỉ có 10
#2 MALFORMED IPv4: cần ít nhất 20 byte, chỉ có 12
#3 MALFORMED IPv4: IHL=3 nhỏ hơn 5 (header tối thiểu 20 byte)
#4 192.168.10.5 -> 93.184.216.34 TCP MALFORMED TCP: data offset=3 nhỏ hơn 5 (header tối thiểu 20 byte)
#5 192.168.10.5 -> 8.8.8.8 UDP MALFORMED UDP: length=4 nhỏ hơn header 8 byte
#6 192.168.10.5:51032 -> 8.8.8.8:53 UDP len=18 app=DNS(port) query (malformed: Con trỏ nén tạo vòng lặp tại vị trí 12)
#7 192.168.10.5:51033 -> 8.8.8.8:53 UDP len=5 app=DNS(port) MALFORMED DNS: cần ít nhất 12 byte header, chỉ có 5
#8 192.168.10.5:51034 -> 93.184.216.34:80 TCP [PSH/ACK] seq=0 ack=0 win=8192 len=29 app=HTTP(payload+port) GET http://ÿþ/
#9 192.168.10.5 -> 93.184.216.34 TCP MALFORMED TCP: cần ít nhất 20 byte, chỉ có 10 (truncated)
Đã xử lý 9 gói, ghi 9 sự kiện vào TEST/cases/12_malformed_packet/output.jsonl (malformed: 8, bỏ qua: 0)
```
