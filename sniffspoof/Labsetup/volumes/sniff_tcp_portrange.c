#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

/* Ethernet Header */
struct ethheader {
	u_char ether_dhost[6]; /* Destination host address */
	u_char ether_shost[6]; /* Source host address */
	u_short ether_type;    /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
	unsigned char		iph_ihl:4, //IP header length
				iph_ver:4; //IP version
	unsigned char 		iph_tos;   //Type of Service
	unsigned short int	iph_len;   //Packet Length
	unsigned short int	iph_ident; //Identification
	unsigned short int	iph_flag:3,//Fragmentation flags
				iph_offset:13; //Flags offset
	unsigned char		iph_ttl;   //Time to live
	unsigned char		iph_protocol; //Protocol type
	unsigned short int	iph_chksum;//IP datagram checksum
	struct	in_addr		iph_sourceip; // Source IP address
        struct  in_addr         iph_destip;   // Destination IP address
};

/* TCP Header */
struct tcpheader {

	unsigned short int 	tcph_sport;	// Source Port
        unsigned short int	tcph_dport;     // Destination Port
	unsigned int		tcph_seq;	// Sequence number
	unsigned int		tcph_ack;	// Acknowledgement Number
	unsigned char		tcph_offs;	// data offset
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	unsigned char		tcph_flags;	// TCP flags
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	unsigned short int	tcph_win;	// Window
	unsigned short int	tcph_sum;	// checksum
	unsigned short int	tcph_urp;	// urgent pointer
	
};


/* This Function will be invoked by pcap for each captured packer.
 * We can process each packet inside the function
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	
	unsigned int ip_size;

	// Cast the pointer to the packet as a ethheader struct
	struct ethheader *eth = (struct ethheader *)packet;
	
	// We cast the type of the data after the ether header in the packet to an IP struct
	if ( ntohs(eth->ether_type) == 0x800 ) { // 0x800 is IP type
		struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader));
		// To get the tcp header we cast the type of the data. 
		// We need to multiply the IP header length 4 times(since iph_ihl is the length in bytes)
		// And that will put our pointer to the start of the TCP header.
		ip_size = ip->iph_ihl * 4;
		struct tcpheader * tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_size);
		
		printf("	From: %s\n", inet_ntoa(ip->iph_sourceip));
        	printf("          To: %s\n", inet_ntoa(ip->iph_destip));

		/* Determine protocol */
		switch(ip->iph_protocol) {
			case IPPROTO_TCP:
				printf("	Protocol: TCP\n");
				printf("        PORT DESTINATION: %hu\n", ntohs(tcp->tcph_dport));
				return;
			case IPPROTO_UDP:
				printf("        Protocol: UDP\n");
                        	return;
			case IPPROTO_ICMP:
				printf("        Protocol: ICMP\n");
                        	return;
			default:
				printf("        Protocol: Others\n");
                        	return;
		}
	}
}

int main()
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	// Filter expression to capture between Host container and VM
        char filter_exp[] = "tcp dst portrange 10-100";

	bpf_u_int32 net;
	
	// Step 1: Open live pcap session on NIC with name
	// br-0229d0abdb25
	handle = pcap_open_live("br-0229d0abdb25", BUFSIZ, 0, 1000, errbuf);

	// Step 2: Comple filter_exp into BPF pseudo-code
	pcap_compile(handle, &fp, filter_exp, 0, net);
	if (pcap_setfilter(handle, &fp) != 0) {
		pcap_perror(handle, "Error:");
		exit(EXIT_FAILURE);
	}

	// Step 3: Capture Packets
	pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle); //Close the handle
	return 0;
}
