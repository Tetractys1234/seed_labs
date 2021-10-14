ARP Cache Poisoning Attack Lab
-------------------------------

#Overview
---------

Address Resolution Protocol is a communication protocol used for discovering link layer addresses. It is a simple protocol that does not implement any securit measures. 


#Lab Environment
----------------

To complete this lab I am using the lab setup provided by the [SEED security labs](https://seedsecuritylabs.org/Labs_20.04/Files/ARP_Attack/ARP_Attack.pdf).

Our container network will look like this:

![arpnetwork](img/arpnetwork.png)

From the VM the interface I will be sniffing packets on is br-758189db12f0.

We have 3 machines, for reference I will post their MAC Addresses here.

M-02:42:0a:09:00:69
B-02:42:0a:09:00:06 
A-02:42:0a:09:00:05 

## Task 1.A
------------
On host M we need to construct an ARP request packet and send it to host A. Then check A's arp cache to see if this works.

In order to construct the packet correctly with scapy we need to fill in the correct fields in the ARP request we send.
Opening a python shell we can see what the fields of the ARP packet in scapy are

```python3
>>> from scapy.all import *
>>> ls(ARP)
hwtype     : XShortField                         = (1)
ptype      : XShortEnumField                     = (2048)
hwlen      : FieldLenField                       = (None)
plen       : FieldLenField                       = (None)
op         : ShortEnumField                      = (1)
hwsrc      : MultipleTypeField                   = (None)
psrc       : MultipleTypeField                   = (None)
hwdst      : MultipleTypeField                   = (None)
pdst       : MultipleTypeField                   = (None)
```

In order to construct a request packet we need to fill in the correct header values. So we know M (our malicious machine) needs to be implanted in A's ARP cache as hardware address that is to receive traffic for 10.9.0.6 (B). Ok so we will have
`hwsrc = 02:42:0a:09:00:69` as the ehternet source of the ARP broadcast request. We will set the `psrc = 10.9.0.6`, this indicates the Sender protocol address. Now we need to target A's machine so set `hdst = 02:42:0a:09:00:05` as the hardware target address and `pdst= 10.9.0.5`. Lastly we need to give the operation code for the packet so `op=1` 1 is for a request, 2 is for a reply.

Using scapy to construct the packet we have something like this (arpconstruct.py)
```python3
#!/usr/bin/env python3
from scapy.all import *

'''
E=Ether()
## Arp sent from M to A, mapping M's MAC to B's address in A's ARP cache
A=ARP(hwsrc='02:42:0a:09:00:69', psrc ='10.9.0.6', hwdst= '02:42:0a:09:00:05', pdst = '10.9.0.5')

pkt = E/A
sendp(pkt, iface='eth0')
```

So I then send out the request and observe what happens over the interface eth0 on our VM.

![wshark1request](img/wshark1request.png)

The first broadcast that is sent out is from our own machine with its own IP address as the source. Why? because the malicious machine does not know the route to 10.9.0.5. This results in the first packet revealing our 10.9.0.105 address to A

![firstpacketrequest](img/firstpacketrequest.png)

And A's arp cache now looks like this:

![aarpcacherequest](img/aarpcacherequest.png)


Importantly I need to see if this works, will A send packets to M instead of B?

So I conduct an experiment with the ping program

![doesrequestwork](img/doesrequestwork.png)

Sending a ping to 10.9.0.6

We trace the traffic with wireshark

![duplicatedetected](img/duplicatedetected.png)

We see the ping get sent out to our machine's address (M) 

![ping](img/ping.png)

But our machine has no idea where 10.9.0.6 is, which causes it to broadcast an ARP request over the network trying to find 10.9.0.6

The real 10.9.0.6 follows up with an ARP response broadcasted over the network segment letting all the machines connected know that it is actually located at. Now our Machine updates its ARP cache sends the ping from 10.9.0.105 to 10.9.0.6. Since the source of the packet is 10.9.0.5 and machine B has never communicated with it before, it sends out an ARP request to fill in its ARP cache with A's information. At this point a duplicate entry is detected in A's ARP cache and now the whole network knows that the ARP cache was wrong to begin with.

![duplicatedetected](img/duplicatedetected.png) 

And we can see in A's ARP cache the address is changed to the correct location of 10.9.0.6 and also our machine 10.9.0.105 has been revealed to both A and B and no traffic will be routed between them anymore unless we resend the spoofed ARP request. So this isn't really ideal for a man in the middle situation.


#Task1.B Using ARP reply

So lets construct an ARP reply packet and see if that will work better.

Scenario 1: B's IP is already in A's cache.
Scenario 2: B's IP is not in A's cache.

