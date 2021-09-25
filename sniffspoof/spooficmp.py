#!/usr/bin/env python3

# TASK 1.2 Spoofing ICMP packets

from scapy.all import *

# We will construct a ICMP packet layer by layer and send it
def spoof_icmp():
    
    print("SENDING SPOOFED ICMP------------\n")
    a = IP()
    a.dst = '10.9.0.5'
    a.src = '1.2.3.4'
    b = ICMP()
    pkt = a/b
    send(pkt)

spoof_icmp()
