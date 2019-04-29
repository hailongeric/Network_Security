#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <netinet/in.h> 

#define BUFF_SIZE 2000
#define PORT_NUMBER 4433
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CA_DIR "ca_client" 

struct sockaddr_in server_addr;

int createTunDevice() {
	int tunfd;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	tunfd = open("/dev/net/tun", O_RDWR);
	ioctl(tunfd, TUNSETIFF, &ifr);

	return tunfd;
}

int connectToTCPServer(const char* hostname) {
	int sockfd;
	// Get the IP address from hostname
	struct hostent* hp = gethostbyname(hostname);

	// Fill in the destination information (IP, port #, and family)
	memset(&server_addr, 0, sizeof(server_addr));
	memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(PORT_NUMBER);
	// server_addr.sin_addr.s_addr = inet_addr ("10.0.2.14");

	 // Create a TCP socket
	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// Connect to the destination
	connect(sockfd, (struct sockaddr*) &server_addr, sizeof(server_addr));

	return sockfd;
}

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
	char  buf[300];

	X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
	X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
	printf("subject= %s\n", buf);
	if (preverify_ok == 1) {
		printf("Verification passed.\n");
	}
	else {
		int err = X509_STORE_CTX_get_error(x509_ctx);
		printf("Verification failed: %s.\n",
			X509_verify_cert_error_string(err));
	}
}


SSL* setupTLSClient(const char* hostname) {
	// Step 0: OpenSSL library initialization 
   // This step is no longer needed as of version 1.1.0.
	SSL_library_init();
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	SSL_METHOD *meth;
	SSL_CTX* ctx;
	SSL* ssl;

	meth = (SSL_METHOD *)TLSv1_2_method();
	ctx = SSL_CTX_new(meth);

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
	if (SSL_CTX_load_verify_locations(ctx, NULL, CA_DIR) < 1) {
		printf("Error setting the verify locations. \n");
		exit(0);
	}
	ssl = SSL_new(ctx);

	X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
	X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

	return ssl;
}




void tunSelected(int tunfd, SSL* ssl) {
	int  len;
	char buff[BUFF_SIZE];

	printf("Got a packet from TUN\n");

	bzero(buff, BUFF_SIZE);
	len = read(tunfd, buff, BUFF_SIZE);
	/*----------------Send data --------------------*/
	SSL_write(ssl, buff, len);
}

void socketSelected(int tunfd, SSL* ssl) {
	int  len;
	char buff[BUFF_SIZE];

	//printf("Got a packet from the tunnel\n");

	bzero(buff, BUFF_SIZE);

	/*----------------Send/Receive data --------------------*/
	len = SSL_read(ssl, buff, sizeof(buff) - 1);
	write(tunfd, buff, len);
}

int main(int argc, char * argv[]) {
	int tunfd, sockfd;
	char user[12];
	char passwd[12];

	char *hostname = "www.yahoo.com";
	unsigned int use_tunfd_ip;
	// 格式  ./vpn_tls_client hailong:xxx@Hailong.com 
	
	char user_name[10];
	size_t i =0 ;
	size_t j =0 ;
	
	if (argc > 2&&strchr(argv[1],':')!=NULL&&strchr(argv[1],'@')!=NULL){
		i = (size_t)(strchr(argv[1],':')-argv[1]);
		j = (size_t)(strchr(argv[1],'@')-argv[1]);
		bzero(user, 12);
		bzero(passwd, 12);
		strncpy(user,argv[1],i);
		strncpy(passwd,argv[1]+i+1,j-i-1);
		hostname = (argv[1]+j+1);
		use_tunfd_ip = (int)inet_addr(argv[2]);
		printf("\nuse tun ip:%x\n",use_tunfd_ip);
	}

	tunfd = createTunDevice();

	/*----------------Create a TCP connection ---------------*/
	sockfd = connectToTCPServer(hostname);

	/*----------------TLS initialization ----------------*/
	SSL *ssl = setupTLSClient(hostname);

	/*----------------TLS handshake ---------------------*/
	SSL_set_fd(ssl, sockfd);
	int err = SSL_connect(ssl);
	CHK_SSL(err);
	printf("SSL connection is successful\n");
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));
	// Enter the main loop
	
	
	// -----login-----
	char buff[30];
	bzero(buff, 30);
	strncpy(buff, user, strlen(user));
	strncpy(buff+12, passwd, strlen(passwd));
	strncpy(buff+24, (char *)(&use_tunfd_ip), sizeof(int));
	SSL_write(ssl, buff, 30);
	bzero(buff, 30);
	SSL_read(ssl, buff, sizeof(buff) - 1);
	printf("%s", buff);
	

	while (1) {
		fd_set readFDSet;

		FD_ZERO(&readFDSet);
		FD_SET(sockfd, &readFDSet);
		FD_SET(tunfd, &readFDSet);
		select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

		if (FD_ISSET(tunfd, &readFDSet)) tunSelected(tunfd, ssl);
		if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, ssl);
	}
}

