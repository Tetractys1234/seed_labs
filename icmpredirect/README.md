#ICMP Redirect Attack Lab
-------------------------

This lab is about creating ICMP redirect. Which is an error message sent by a router to the sender of an IP packet. Redirects are used when a router believes a packet is being routed incorrectly, and it would like to inform the sender that it should use a different router for the subsequent packets sent to that same destination. ICMP redirect can be used by attackers to change a victim's routing.

The objective of this task is to launch an ICMP redirect attack on the victim, such that when the victim sends packets to 192.168.60.5, it will use the malicious router container (10.9.0.111) as its router. Since the malicious router is controlled by the attacker, the attacker can intercept the packets, make changes, and then send the modified packets out. 


## Environment Setup using container
-------------------------------------

As with the other labs we will be using the SEED docker containers in the zip file provided for the lab. Make sure to shut down any other containers that might be running on your lab machine or just start the configuration from a fresh VM. The details for Environment setup can be found on [SEED labs](https://seedsecuritylabs.org/Labs_20.04/Networking/ICMP_Redirect/)

Once the environment is set up, verify that it represents the one SEED wants you to use in the lab.

![netconfig](img/networkconfig.png)

## Task 1: Launching ICMP Redirect Attack

In the Ubuntu OS there is a countermeasure against ICMP redirect attacks. The Containers have been configured to ignore this countermeasure such that the victim will accept redirect messages.

We will attack the Victim container from the Attacker container. Checking the routing on our victim container

![victimroute](img/victimroute)

We see that the Victim container uses the container router to get to the 192.168.60.0/24 network.

Now we will develop a scapy script to Launch an ICMP redirect.
 
 
