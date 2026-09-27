# Case 11: Unknown protocol

**Yêu cầu của đề:** Không crash

**Kết quả: ĐẠT** (8/8 kiểm tra đạt)

## Lệnh chạy

```bash
python main.py --pcap TEST/cases/11_unknown_protocol/input.pcap --output TEST/cases/11_unknown_protocol/output.jsonl
```

Đầu vào: `input.pcap` (6 gói). Đầu ra: `output.jsonl` (6 sự kiện).

## Kiểm tra

| Kiểm tra | Mong đợi | Thực tế | Kết quả |
|---|---|---|---|
| Chương trình kết thúc bình thường (mã thoát 0) | `0` | `0` | ĐẠT |
| Không có traceback (không crash) | `False` | `False` | ĐẠT |
| Số sự kiện (không gói nào bị mất) | `6` | `6` | ĐẠT |
| ARP, IPv6, LLDP: network là UNKNOWN | `['UNKNOWN', 'UNKNOWN', 'UNKNOWN']` | `['UNKNOWN', 'UNKNOWN', 'UNKNOWN']` | ĐẠT |
| Tên EtherType | `['ARP', 'IPv6', '0x88cc']` | `['ARP', 'IPv6', '0x88cc']` | ĐẠT |
| ICMP: transport không phải TCP/UDP | `'ICMP'` | `'ICMP'` | ĐẠT |
| TLS port 443 và dữ liệu lạ port 40000: app UNKNOWN | `['UNKNOWN', 'UNKNOWN']` | `['UNKNOWN', 'UNKNOWN']` | ĐẠT |
| Không gói nào bị coi là hỏng | `0` | `0` | ĐẠT |

## Màn hình

```
#1 ARP UNKNOWN
#2 IPv6 UNKNOWN
#3 0x88cc UNKNOWN
#4 192.168.10.5 -> 93.184.216.34 ICMP
#5 192.168.10.5:51020 -> 93.184.216.34:443 TCP [PSH/ACK] seq=0 ack=0 win=8192 len=66 app=UNKNOWN
#6 192.168.10.5:51021 -> 93.184.216.34:40000 UDP len=29 app=UNKNOWN
Đã xử lý 6 gói, ghi 6 sự kiện vào TEST/cases/11_unknown_protocol/output.jsonl (malformed: 0, bỏ qua: 0)
```
