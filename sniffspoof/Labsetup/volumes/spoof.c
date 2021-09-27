
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

/* Ethernet Header */
struct ethheader {
        u_char ether_dhost[6]; /* Destination host address */
        u_char ether_shost[6]; /* Source host address */
        u_short ether_type;    /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
        unsigned char           iph_ihl:4, // IP header length
                                iph_ver:4; // IP version
        unsigned char           iph_tos;   // Type of Service
        unsigned short int      iph_len;   // Packet Length
        unsigned short int      iph_ident; // Identification
        unsigned short int      iph_flag:3,// Fragmentation flags
                                iph_offset:13; // Flags offset
        unsigned char           iph_ttl;   // Time to live
        unsigned char           iph_protocol; // Protocol type
        unsigned short int      iph_chksum;// IP datagram checksum
        struct  in_addr         iph_sourceip; // Source IP address
        struct  in_addr         iph_destip;   // Destination IP address
};

/* TCP Header */
struct tcpheader {

        unsigned short int      tcph_sport;     // Source Port
        unsigned short int      tcph_dport;     // Destination Port
        unsigned int            tcph_seq;       // Sequence number
        unsigned int            tcph_ack;       // Acknowledgement Number
        unsigned char           tcph_offs;      // data offset
#define TH_OFF(th)      (((th)->tcph_offs & 0xf0) >> 4)
        unsigned char           tcph_flags;     // TCP flags
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        unsigned short int      tcph_win;       // Window
        unsigned short int      tcph_sum;       // checksum
        unsigned short int      tcph_urp;       // urgent pointer

};


/* ICMP header */

struct icmpheader {
	unsigned char	icmp_type;      // ICMP message type
	unsigned char	icmp_code;      // error code
	unsigned short int icmp_chksum; //Checksum for ICMP header and data
	unsigned short int icmp_seq;    // Sequence number
};

unsigned short in_cksum (unsigned short *buf, int length);
void send_raw_ip_packet (struct ipheader* ip);

/***********************************************************************
 * Given a IP packet, send it out using a raw socket.
 ***********************************************************************/
void send_raw_ip_packet (struct ipheader* ip)
{
	
}



/* Spoof an ICMP echo request using an arbitrary IP address */
int main {

	char buffer[1500];
	memset(buffer, 0, 1500);

	/******************************
	 1. Fill in the ICMP header
	******************************/
	
	struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
	icmp->icmp_type = 8; // Type 8 is echo request, 0 is reply.

	//Calculate checksum for integrity
	icmp->icmp_chksum = 0;
	icmp->icmp_chksum = in_cksum((unsigned short *) icmp, sizeof(struct icmpheader));

	/******************************
	 2. Fill in the IP Header
	******************************/

	struct ipheader *ip = (struct ipheader *) buffer;
	ip->iph_ver = 4;
	ip->iph_ihl = 5;
	ip->iph_ttl = 20;
	ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
	ip->iph_destip.s_addr = inet_addr("10.9.0.5");
	ip_>iph_protocol = IPPROTO_ICMP;
	ip_>iph_len = htons(sizeof(struct ipheader) + sizeof(stuct icmpheader));

	/*******************************
	 3. Send the spoofed packet
	******************************/

	send_raw_ip_packet(ip);

	return 0;

}
