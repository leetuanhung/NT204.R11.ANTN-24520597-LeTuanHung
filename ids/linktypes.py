"""Mã linktype theo chuẩn libpcap (https://www.tcpdump.org/linktypes.html).

Linktype cho parser biết header lớp 2 của frame có dạng gì,
từ đó biết header IP bắt đầu ở byte thứ mấy.
"""

LINKTYPE_ETHERNET = 1       # Ethernet II: 14 byte header
LINKTYPE_RAW = 101          # Không có header lớp 2, bắt đầu thẳng bằng IP
LINKTYPE_LINUX_SLL = 113    # Linux "cooked" capture v1: 16 byte header
LINKTYPE_LINUX_SLL2 = 276   # Linux "cooked" capture v2: 20 byte header
