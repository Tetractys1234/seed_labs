#!/usr/bin/env python3

import sys
from scapy.all import *

# We will use scapy as an ICMP traceroute tool
#--Program is interactable, change address and ttl as you like with
#  command line arguments
# REF: https://0xbharath.github.io/art-of-packet-crafting-with-scapy/network_recon/traceroute/index.html

def scapy_traceroute(addr, ttl):
    
    ans,unans=sr(IP(dst=addr,ttl=(1,ttl))/ICMP(), timeout=5)
    ans.summary( lambda s,r : r.sprintf("%IP.src% CODE: %ICMP.type%"))
    

if __name__ == "__main__":
    
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Simple Scapy traceroute program:\n",
              "USAGE: traceroute.py [ADDRESS] , [TTL]")
        sys.exit(0)

    else:
        addr = sys.argv[1]
        ttl = int(sys.argv[2])
        scapy_traceroute(addr, ttl)

