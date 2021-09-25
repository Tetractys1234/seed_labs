#!/usr/bin/env python3

from scapy.all import *

# This default print_pkt from SEED Lab
def print_pkt(pkt):
    pkt.show()

# pkt.show() is giving us too much information for testing out
# filters. Lets use some formatting from 
# https://scapy.readthedocs.io/en/latest/usage.html#reading-pcap-files
def pprint_pkt(pkt):
    # Print out showing Origin IP:port -> Dest IP:port
    print(pkt[IP].src + "->" + pkt[IP].dst)

# Demo the sniffer on our container network interface
# pkt = sniff(iface='br-0229d0abdb25' , filter='icmp', prn=print_pkt)

#Task 1.1B --- Capturing only the ICMP packets
def icmp_only():
    print("CAPTURING ICMP -------------\n")
    pkt = sniff(iface='br-0229d0abdb25' , filter='icmp', prn=pprint_pkt)

#Task 1.1B --- Capturing only TCP packets going to port 23
def tcp_port23():
    print("CAPTURING TCP PORT 23 HOST 9.9.9.9 -------------\n")
    pkt = sniff(iface='br-0229d0abdb25', filter='tcp and host 9.9.9.9 and port 23', prn=pprint_pkt)

#Task 1.1B --- Capturing packets FROM a subnet
def tofrom_subnet():
    print("CAPTURING 1.0.0.0/8 PACKETS")
    pkt = sniff(iface='enp0s3', filter='net 1.0.0.0 mask 255.0.0.0', count=1,prn=pprint_pkt)

################################################################################

# Run tasks
#icmp_only()
#tcp_port23()
tofrom_subnet()

################################################################################
