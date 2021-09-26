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


/* This Function will be invoked by pcap for each captured packer.
 * We can process each packet inside the function
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	// Cast the pointer to the packet as a ethheader struct
	struct ethheader *eth = (struct ethheader *)packet;
	
	// We cast the type of the data after the ether header in the packet to an IP struct
	if ( ntohs(eth->ether_type) == 0x800 ) { // 0x800 is IP type
		struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader));
	

		printf("	From: %s\n", inet_ntoa(ip->iph_sourceip));
        	printf("          To: %s\n", inet_ntoa(ip->iph_destip));

		/* Determine protocol */
		switch(ip->iph_protocol) {
			case IPPROTO_TCP:
				printf("	Protocol: TCP\n");
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
	char filter_exp[] = "icmp";
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
