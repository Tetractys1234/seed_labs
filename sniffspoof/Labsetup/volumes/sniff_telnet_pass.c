
/*
 * sniff_telnet_pass.c
 *
 * Sniffer example of TCP/IP packet capture using libpcap.
 *
 * Version 0.1.1 (2005-07-05)
 * Copyright (c) 2005 The Tcpdump Group
 *
 * This software is intended to be used as a practical example and
 * demonstration of the libpcap library; available at:
 * http://www.tcpdump.org/
 *
 ****************************************************************************
 *
 * This software is a modification of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 *
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 *
 * "sniffer.c" is distributed under these terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The name "Tim Carstens" may not be used to endorse or promote
 *    products derived from this software without prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * <end of "sniffer.c" terms>
 */

/* 
 * I, Keith Sabine, am using parts of Tim Carsten's code in order to
 * understand and learn how to create packet capturing tools. This is
 * not a complete reproduction of the code provided at Tim Carsten's
 * tutorial, but it is derivative of it. I have used the same TCP header
 * and will use his functions to print the TCP payload in order to show
 * the telnet data I need to complete the tasks in the SEED lab. I am also
 * using code from Computer Internet and Security, Wenliang Du chapter 15
 * Packet Sniffing and Spoofing.
 */

#define APP_NAME		"sniff_telnet_pass"
#define APP_DESC		"Sniffer example using libpcap"

#include <string.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>

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
#define TH_OFF(th)	(((th)->tcph_offs & 0xf0) >> 4)
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

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

/* This Function will be invoked by pcap for each captured packer.
 * We can process each packet inside the function
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	
	unsigned int ip_size;
	unsigned int tcp_size;
	unsigned int size_payload;
	const char *payload;

	// Cast the pointer to the packet as a ethheader struct
	struct ethheader *eth = (struct ethheader *)packet;
	
	// We cast the type of the data after the ether header in the packet to an IP struct
	if ( ntohs(eth->ether_type) == 0x800 ) { // 0x800 is IP type
		struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader));
		ip_size = ip->iph_ihl * 4;
		

		/* Determine protocol */
		switch(ip->iph_protocol) {
			case IPPROTO_TCP:
				break;
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

	/* define/compute tcp header offset */
	struct tcpheader * tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_size);
	tcp_size = TH_OFF(tcp)*4;
	
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + sizeof(struct ethheader) + ip_size + tcp_size);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->iph_len) - (ip_size + tcp_size);

	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
		if (size_payload > 0) {
			printf("   Payload (%d bytes):\n", size_payload);
			print_payload(payload, size_payload);
		}
	}
	return;
}

int main()
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	// Filter expression to capture between Host container and VM
        char filter_exp[] = "tcp portrange 10-100";

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
