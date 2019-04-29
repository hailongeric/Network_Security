#include <pcap.h>
#include <stdio.h>
#include <unistd.h>
#include <stdio.h>
#include<sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include<string.h>
#include<stdlib.h>
#include<arpa/inet.h>

/* This function will be invoked by pcap for each captured packet.
*We can process each packet inside the function.
*/
/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};
// headers' structures
// IP header's structure
struct sniff_ip {
 unsigned char      iph_ihl:4, /* Little-endian */
                    iph_ver:4;
 unsigned char      iph_tos;
 unsigned short int ip_len;
 unsigned short int ip_id;
 unsigned short int ip_off:13,
		    iph_flags:3;		    
 unsigned char      ip_ttl;
 unsigned char      ip_p;
 unsigned short int ip_sum;
 unsigned int       ip_src;
 unsigned int       ip_dst;;
};


/* Structure of a ICMP header */
struct icmpheader {
 unsigned char type;
 unsigned char code;
 unsigned short int icmph_chksum;
 unsigned short int  id;
 unsigned short int  sequence;
 unsigned char time[8];
};

// Simple checksum function, may use others such as Cyclic Redundancy Check, CRC
unsigned short csum(unsigned short *buf, int len){
        unsigned long sum;
        for(sum=0; len>0; len--){
		//printf("%4x\n",*buf);
                sum += *buf++;
	}
        sum = (sum >> 16) + (sum &0xffff);
        sum += (sum >> 16);
        return (unsigned short)(~sum);
}
	
void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{
	struct sniff_ethernet *ethernet; /* The ethernet header */
	struct sniff_ip *ip; /* The IP header */
	struct icmpheader *icmp; /* The ICMP header */
	// char *payload; /* Packet payload */
	u_int src_ad,dst_ad;
        char buffer[1024];
	int sd;	

	u_int size_ip;
	u_int size_icmp;
        memcpy(buffer,packet ,1024);
	ethernet = (struct sniff_ethernet*)(buffer);
	u_char temp;
	int k=0;
	for(k=0;k<ETHER_ADDR_LEN;k++){
		temp=ethernet->ether_dhost[k];
		ethernet->ether_dhost[k]= ethernet->ether_shost[k];
		ethernet->ether_shost[k] = temp;
	}

	ip = (struct sniff_ip*)(buffer + SIZE_ETHERNET);
	size_ip = ip->iph_ihl*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	icmp = (struct icmpheader*)(buffer + SIZE_ETHERNET + size_ip);
	size_icmp = 16;
	if (size_icmp < 16) {
		printf("   * Invalid TCP header length: %u bytes\n", size_icmp);
		return;
	}
	if(icmp->type != 8)
		return;	
	struct hostent *hp, *hp2;
	struct sockaddr_in sin, din;	
	int one = 1;	
	const int *val = &one;	 
	//memset(buffer, 0, PCKT_LEN);
		
	sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(sd < 0){	
		perror("socket() error");	
		exit(-1);	
	}else	
		printf("socket()-SOCK_RAW and icmp protocol is OK.\n");
		
	// The source is redundant, may be used later if needed
	
	// Address family	
	sin.sin_family = AF_INET;
	din.sin_family = AF_INET;
	
	
	// Source IP, can be any, modify as needed	
	sin.sin_addr.s_addr = ip->ip_src;
	din.sin_addr.s_addr = ip->ip_dst;
	
	ip->ip_id = htons(428);	
	ip->ip_off = 0;
	ip->ip_ttl = 43;		
	ip->ip_sum = 0; // Done by kernel		 	

	dst_ad = ip->ip_src;
	// Source IP, modify as needed, spoofed, we accept through command line argument	
	ip->ip_src = ip->ip_dst;	
	// Destination IP, modify as needed, but here we accept through command line argument	
	ip->ip_dst= dst_ad;	
	
	// Inform the kernel do not fill up the headers' structure, we fabricated our own
	if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL,val, sizeof(one)) < 0){	
		perror("setsockopt() error");	
		exit(-1);	
	}else	
		printf("setsockopt() is OK\n");	
	//printf("type :%d\n",icmp->type); 
	icmp->type=0;
	icmp->icmph_chksum = 0;
	icmp->icmph_chksum=csum((unsigned short *) (buffer+sizeof(struct sniff_ip)+SIZE_ETHERNET), (sizeof(struct icmpheader) + 48)/2);
	
	// IP checksum calculation	
	ip->ip_sum = 0;
	ip->ip_sum = csum((unsigned short *) (buffer+SIZE_ETHERNET), (sizeof(struct sniff_ip) + sizeof(struct icmpheader)+48)/2);	 
			
	unsigned short int pack_len = ((ip->ip_len>>8)&0xff+(ip->ip_len<<8)&0xffff);
        printf("pacek_len :%x %x\n",pack_len,ip->ip_len);	
	if(sendto(sd, (buffer+SIZE_ETHERNET),pack_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)		
	// Verify		
	{		
		perror("sendto() error");	
		exit(-1);		
	}else		
		printf("Count # - sendto() is OK\n");				
	close(sd);
	//printf("%s",payload);
}
int main()
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "icmp";
	bpf_u_int32 net;
	// Step 1: Open live pcap session on NIC with name eth3
	// Students needs to change "eth3" to the name
	// found on their own machines (using ifconfig).
	handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
	// Step 2: Compile filter_exp into BPF psuedo-code
	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);
	// Step 3: Capture packets
	pcap_loop(handle, -1, got_packet, NULL);
	pcap_close(handle); //Close the handle
	return 0;
}
// Note: don’t forget to add "-lpcap" to the compilation command.
// For example: gcc -o sniff sniff.c -lpcap
