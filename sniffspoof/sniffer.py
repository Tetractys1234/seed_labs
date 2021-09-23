#!/usr/bin/env python3

from scapy.all import *

def print_pkt(pkt):
    pkt.show()

pkt = sniff(iface='br-7576105bbb17' , filter='icmp', prn=print_pkt)

