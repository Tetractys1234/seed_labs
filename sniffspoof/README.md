
# Packet Sniffing and Spoofing


### Intro

My name is Keith Sabine and I will be working through this SEED security lab as
part of my Undergrad CS studies. 

### Some notes

All of the machine configurations are available on the SEED website.( https://seedsecuritylabs.org/Labs_20.04/Networking/Sniffing_Spoofing/ ). I will only be posting my progress and observations as I work through the lab and answer the questions it requires. I set up the SEED VM using the Ubuntu 20.04 VM config. I will be completing both Task 1 and Task 2.


Environment Setup using Container
----------------------------------
You can download the Labsetup.zip from the Lab website which contains scripts to set up Docker Images. I have never worked with Docker before so this step has been new for me. The lab gives us some commands to build and the SEED VM setup gave us a nice bash config to make these commands easy.

Once you compose the docker images you can use the alias command `dcup` to boot up our Docker network

![dcup](img/dockerstart.png)

Next I want to make sure I am able to have a shell open in both the attacker and the host machine for quick testing and reference so I use more of the commands in docker in seperate terminal windows for easy access between the VM and the two docker machines. Use `dockps` to find the ID and the Name of each docker image and then activate a shell in each I named my terminal windows ATTACK and DOCKHOST for the shells I am using in each `docker exec -it dc /bin/bash/` opens the shell @ root level.

![dockps](img/dockps.png)

The final part of setting up requires getting the network interface that our Docker images will be communicating over. The docker-compose.yml script shows that we have assigned the IP 10.9.0.0/24 to the network so we will need to identify the network device on our VM that matches the script setup. So lets check `ifconfig`

![ifconfig](img/ifconfig.png)

We see the device name on my machine is br-8928c17f4ab4 this is important so I copy it into a textfile for use later.

The Docker is set up and I have the terminals open! Things are looking good so far, but there is a lot more to learn about docker and the environment we have set up here beyond the basic instructions provided by the lab. Seed has posted a comprehensive tutorial for using Docker with their labs and I will keep the link for reference [Docker Tutorial](https://github.com/seed-labs/seed-labs/blob/master/manuals/docker/SEEDManual-Container.md)

Using Scapy to Sniff and Spoof Packets
--------------------------------------

Scapy is a Python program enabling user to send, sniff, dissect, and forge network packets. Time to learn a bit about it for the upcoming tasks!

running the example script:
```python 
from scapy.all import * #We import all modules from Scapy to use
a = IP()
a.show()
```
creates an IP packet for us

![ippacket](img/scapyintro.png)

Lets use Scapy to do some packet sniffing for us.

### Task 1.1 Sniffing Packets

We are going to take the sample code and run it on our vm, you can find the script in the repo or simply copy/paste it, but be careful as your interface name may be different. notice how sniff requires an interface name, iface, to be specified. iface can be one interface or multiple (use a list).
```python

#!/usr/bin/env python3

def print_pkt(pkt):
	pkt.show()

pkt = sniff(iface='br-8928c17f4ab4' , filter='icmp', prn=print_pkt)


```
#### Task 1.1A

We will sniff from the VM to start. The filter is set for ICMP packets so lets send a ping to the container network interface. Don't forget that root privilege will be needed to view packets. Sending a ping to the br-8928c17f4ab4 interface from the ATTACK container we can sniff the ICMP activity from our VM.

![attackping](img/attackping.png)

Ping sent!

![icmpreceived](img/icmpscapy.png)

Running the same program without root privilege results in an Operation not permitted value. Why? Direct access to network devices is restricted to root users. If you didnt need root privilege then every user on a system could potentially control network adapters which would be a bad idea.

#### Task 1.1B 

After messing around with Scapy for awhile trying to get its built in sprintf function to work I caved and created a print function
to neatly display the ICMP traffic like \[SOURCE\] -> \[DEST\]. Now we can test out the filter functionality in scapy.

First we create a packet on the attacker container using scapy
![scapypacket](img/scapysend.png)

Then with our sniffer.py running a new function: 
```python
#Task 1.1B --- Capturing only the ICMP packets
def icmp_only():
    pkt = sniff(iface='br-8928c17f4ab4' , filter='icmp', prn=pprint_pkt)
```
We see the ICMP packets neatly on the VM
![icmpsniff](img/icmpsniff.png)

And say we want to send a TCP packet on the same interface, we get no packets showing on our VM terminal. Thanks BPF!

The next task requires us to capture ANY TCP packets that come from a particular IP with a destination port 23. Using the filter option in the sniff() function from scapy allows us to accomplish this simply.

We use the filters option in sniff() scapy function like this:
```python
#Task 1.1B --- Capturing only TCP packets going to port 23
def tcp_port23():
    pkt = sniff(iface='br-8928c17f4ab4', filter='tcp and host 9.9.9.9 and port 23', prn=pprint_pkt)
```

Crafting and sending a packet on my attacking machine gets us no response from the sniffer

![tcpwrong](img/tcpwrong.png)

![nothing](img/nothingsniff.png)

When the packet is set to what we filter for however we receive results.

![tcpright](img/tcpright.png)

![tcpsniff](img/tcpsniff.png)

The next task is to set the filter to capture packets coming from or going to a particular subnet. So pick any subnet that the VM is not attached to and try it out. Since we don't want a subnet the VM is attached to we need to change the interface we are observing. So I used the filter function to search for traffic on the internet facing interface. I then sent a ping to 1.2.3.4 and captured it leaving the attacker container to its destination. I used a class A subnet 
```python
#Task 1.1B --- Capturing packets FROM a subnet
def tofrom_subnet():
    pkt = sniff(iface='enp0s3', filter='net 1.0.0.0 mask 255.0.0.0', count=1,prn=pprint_pkt)
```

With this in the python script I sent a packet from my Attacker container to 1.2.3.4
![pingsubnet](img/pingsubnet.png)

The filter worked!

![subnetsniff](img/subnetsniff.png)

### TASK 1.2 Spoofing ICMP Packets

We have already used spoofed packets to easily test our filter settings, but lets go over the deatils here. Scapy makes it really intuitive to create spoofed packets.

```python
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
```

This script comes directly from the SEED lab instructions except we have inserted a new source IP address and when we execute the script and monitor the network device of our attacker machine we can see that the ICMP packet is sent out with the spoofed source IP address. I used wireshark, but our packet sniffer.py would work to see this as well.

![spooficmp](img/spooficmp.png)

### Task 1.3 Traceroute

The SEED labs want us to create a simple traceroute tool with scapy. So we will do like traceroute does and send an echo-request with a time to live of 1 and listen for an ICMP "Time Exceeded" response then increment the time-to-live until we get an ICMP "port unreachable". The last packet we send will either be the max ttl we assigned or the host. For reference I referred to a workshop on scapy from user [0xbharath](https://0xbharath.github.io/art-of-packet-crafting-with-scapy/network_recon/traceroute/index.html) on github

```python
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
```

This simple tool will output the IP of the source from the packets received as well as the code received at the end. The ICMP codes are important to a tool like traceroute as they allow us to know at what point we reach the destination, or at what point are our probes stopped. A difference in this program is that the scapy sr() function has been given a range of packets to send. It will send ALL packets at once and not one by one like a traceroute -I \[address\] will give us.

![traceroutepy](img/traceroutepy.png)

In my example you see the tool probing two addresses. I didn't refine it further since there is still much more to go through in the lab!


### Task 1.4 Sniffing and-then Spoofing

Now we will use scapy to create a Sniff and-then Spoof program. It will run on the VM and interact with the User container. The Computer and Internet Security book by Wenliang Du gives us a nice example to use for the program. I've adapted it for the exercise. REMEMBER!!! The network interface on your setup will be different than mine so be sure to specify the correct iface. I ran these commands from the host interface while sniff_spoof_icmp.py was running from my vm:

`ping -c 4 google.com` An existing host on the internet

`ping -c 4 1.2.3.4` A non-existing host on the internet

`ping -c 4 10.9.0.99` A non-existing host on the LAN

`ping -c 4 8.8.8.8` Another existing host on the internet.

The python program appeared to work! At least for the existing hosts outside of the local network.

![pingspoofs](img/pingspoofs.png)

So why did the local LAN request not go through? We need to understand how the host machine is determining the location of 10.9.0.99, which is the ARP protocol. This is what happened over the network interface when the ping to 10.9.0.99 was sent:

![pingspoofshark](img/pingspoofshark.png)

Because 10.9.0.5 and 10.9.0.99 are on the same subnet (remember we set up the machines using the docker-compose.yml script? Yea its in there! The script assigns the network 10.9.0.0 to a subnet:

```
networks:
    net-10.9.0.0:
        name: net-10.9.0.0
        ipam:
            config:
                - subnet: 10.9.0.0/24
```

Visually our network looks like this: (The VM is outside of the subnet, but still has access to the network device)

![subnet](img/subnet.png)

When the Host machine tries to create a connection with another machine on its own subnet it first needs to know 10.9.0.99 's MAC address. Since there are no replies to the ARP request and the MAC is not stored in the ARP cache on the host machine a connection cannot be made. Ultimately this is why ARP exists, to route traffic on a LAN through the correct interfaces. Unless we modify our python code to also sniff and then spoof an ARP reply our host machine will not know how to communicate with 10.9.0.99 and the ping to it will never be able to be sent.

[Packet Sniffing/Spoofing Lab](https://seedsecuritylabs.org/Labs_20.04/Networking/Sniffing_Spoofing/)
