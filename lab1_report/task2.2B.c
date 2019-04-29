#include <unistd.h>
#include <stdio.h>
#include<sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include<string.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<sys/time.h>

// Packet length
#define PCKT_LEN 8192

// May create separate header file (.h) for all
// headers' structures
// IP header's structure
struct ipheader {
 unsigned char      iph_ihl:4, /* Little-endian */
                    iph_ver:4;
 unsigned char      iph_tos;
 unsigned short int iph_len;
 unsigned short int iph_ident;
 unsigned short int iph_offset:13,
		    iph_flags:3;		    
 unsigned char      iph_ttl;
 unsigned char      iph_protocol;
 unsigned short int iph_chksum;
 unsigned int       iph_sourceip;
 unsigned int       iph_destip;
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

int main(int argc, char *argv[]){



	int pid;
        int ipid = 0;
	int sd;
		// No data, just datagram	
	char buffer[PCKT_LEN];

	// The size of the headers
	struct ipheader *ip = (struct ipheader *) buffer;	
	struct icmpheader *icmp = (struct icmpheader *) (buffer + sizeof(struct ipheader));	
	char *data = (buffer + sizeof(struct ipheader)+ sizeof(struct icmpheader));
   	struct hostent *hp, *hp2;
	struct sockaddr_in sin, din;	
	int one = 1;	
	const int *val = &one;	 
	
	memset(buffer, 0, PCKT_LEN);

		 	
	if(argc != 3){	
		printf("- Invalid parameters!!!\n");	
		printf("- Usage: %s <source hostname/IP> <target hostname/IP> \n", argv[0]);	
		exit(-1);	
	}
		
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
	sin.sin_addr.s_addr = inet_addr(argv[2]);
	din.sin_addr.s_addr = inet_addr(argv[1]);
	
	// IP structure	
	ip->iph_ihl = 5;	
	ip->iph_ver = 4;	
	ip->iph_tos = 0;
	ip->iph_len = sizeof(struct ipheader) + sizeof(struct icmpheader)+48;	
	ip->iph_ident = htons(43590);	
	ip->iph_offset = 64;
	ip->iph_ttl = 64;	
	ip->iph_protocol = 1; // ICMP	
	ip->iph_chksum = 0; // Done by kernel		 
	
	// Source IP, modify as needed, spoofed, we accept through command line argument	
	ip->iph_sourceip = inet_addr(argv[1]);	
	// Destination IP, modify as needed, but here we accept through command line argument	
	ip->iph_destip = inet_addr(argv[2]);	
	
	// Inform the kernel do not fill up the headers' structure, we fabricated our own
	if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL,val, sizeof(one)) < 0){	
		perror("setsockopt() error");	
		exit(-1);	
	}else	
		printf("setsockopt() is OK\n");		 
	printf("Using:::::Source IP: %s , Target IP: %s .\n", argv[1], argv[2]);
	

	int i=0;
	for(i=0;i<48;i++){
		data[i]=i+8;
	}
	icmp->type=8;
	icmp->code=0;
	pid = getpid();
	icmp->id=htons(pid);
	int j =0;
	for(j=0;j<10;j++){
		icmp->sequence=htons(j+1);
		struct timeval *time_stamp=(struct timeval *)icmp->time;
		gettimeofday(time_stamp,NULL);
		
		icmp->icmph_chksum = 0;
		icmp->icmph_chksum=csum((unsigned short *) (buffer+sizeof(struct ipheader)), (sizeof(struct icmpheader) + 48)/2);
	
		// IP checksum calculation	
		ip->iph_chksum = 0;
		ip->iph_chksum = csum((unsigned short *) buffer, (sizeof(struct ipheader) + sizeof(struct icmpheader)+48)/2);	 
			
		
		if(sendto(sd, buffer, ip->iph_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)		
		// Verify		
		{		
			perror("sendto() error");	
			exit(-1);		
		}else		
			printf("Count #%u - sendto() is OK\n", j);		
		sleep(3);		
	}
	close(sd);	
	return 0;
}
