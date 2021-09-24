#!/usr/bin/env python3

from scapy.all import *

# This default print_pkt from SEED Lab
def print_pkt(pkt):
    pkt.show()

# This default print_pkt is ugly lets use some formatting from 
# https://scapy.readthedocs.io/en/latest/usage.html#reading-pcap-files
def pprint_pkt(pkt):
    # Print out showing Origin IP:port -> Dest IP:port
    print(pkt[IP].src + "->" + pkt[IP].dst)

# Demo the sniffer on our container network interface
# pkt = sniff(iface='br-8928c17f4ab4' , filter='icmp', prn=print_pkt)

#Task 1.1B --- Capturing only the ICMP packets
def icmp_only():
    pkt = sniff(iface='br-8928c17f4ab4' , filter='icmp', prn=pprint_pkt)

#Task 1.1B --- Capturing only TCP packets going to port 23
def tcp_port23():
    pkt = sniff(iface='br-8928c17f4ab4', filter='tcp and host 9.9.9.9 and port 23', prn=pprint_pkt)

#Task 1.1B --- Capturing packets FROM a subnet
def tofrom_subnet():
    pkt = sniff(iface='enp0s3', filter='net 1.0.0.0 mask 255.0.0.0', count=1,prn=pprint_pkt)

################################################################################

# Run tasks
#icmp_only()
#tcp_port23()
tofrom_subnet()

################################################################################
