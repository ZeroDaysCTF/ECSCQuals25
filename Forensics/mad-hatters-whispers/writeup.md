# solution

```python
from scapy.all import rdpcap, TCP, Raw
import re

# Replace with your .pcap file path
pcap_file = "chal.pcap"

# Regex to match "Hello from <ip> to <ip>"
pattern = re.compile(rb"Hello from (\d{1,3}(?:\.\d{1,3}){3}) to (\d{1,3}(?:\.\d{1,3}){3})")

# Read the packets from the file
packets = rdpcap(pcap_file)

# Extract matching messages
src = []
dst = []
d = {}
for pkt in packets:
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        payload = pkt[Raw].load
        match = pattern.search(payload)
        if match:
            src_ip, dst_ip = match.groups()
            p = int(src_ip.decode().split(".")[-1])
            if src_ip not in d.keys():
                d[src_ip] = 1
            else:
                d[src_ip] = d[src_ip] + 1

for i in sorted(d.keys()):
    print(chr(d[i]), end="")
```