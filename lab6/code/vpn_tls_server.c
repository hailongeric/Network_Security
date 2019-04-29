#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <shadow.h> 
#include <crypt.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/types.h>

#define PORT_NUMBER 4433
#define BUFF_SIZE 2000
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }


int createTunDevice() {
	int tunfd;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	tunfd = open("/dev/net/tun", O_RDWR);
	ioctl(tunfd, TUNSETIFF, &ifr);
	return tunfd;
}

int initTCPServer() {
	struct sockaddr_in server;
	int listen_sock;
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(PORT_NUMBER);
	listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	CHK_ERR(listen_sock, "socket");
	int err = bind(listen_sock, (struct sockaddr*) &server, sizeof(server));
	CHK_ERR(err, "bind");
	err = listen(listen_sock, 5);
	CHK_ERR(err, "listen");
	return listen_sock;;
}

void tunSelected(int tunfd, SSL* ssl) {
	int  len;
	char buff[BUFF_SIZE];

	printf("Got a packet from server fd\n");
	bzero(buff, BUFF_SIZE);
	len = read(tunfd, buff, BUFF_SIZE);
	SSL_write(ssl, buff, len);
}

int socketSelected(int tunfd, SSL* ssl) {
	int  len;
	char buff[BUFF_SIZE];

	printf("Got a packet from the tunnel\n");

	bzero(buff, BUFF_SIZE);
	len = SSL_read(ssl, buff, sizeof(buff) - 1);
	write(tunfd, buff, len);
	return len;
}


int login(char *user, char *passwd){ 
	struct spwd *pw; 
	char *epasswd;
	pw = getspnam(user); 
	if (pw == NULL){ 
		return 0; 
	}
	printf("Login name: %s\n", pw->sp_namp); 
	printf("Passwd : %s\n", pw->sp_pwdp);
	epasswd = crypt(passwd, pw->sp_pwdp); 
	if (strcmp(epasswd, pw->sp_pwdp)){ 
		return 0; 
	}
	return 1;
}

int Authentication(SSL* ssl,int fd[2]){
	int  len;
	char buff[BUFF_SIZE];
	char user[12];
	char passwd[12];
	bzero(buff, BUFF_SIZE);
	len = SSL_read(ssl, buff, sizeof(buff) - 1);
	strncpy(user, buff, 12);
	strncpy(passwd, (char*)(buff+12), 12);
	
	unsigned int src_ip = *((int *)(buff+24));
	printf("\nsrc ip:%x\n",src_ip);
	write(fd[1],&src_ip,sizeof(int));
	close(fd[1]); 
	
	if(login(user,passwd)){
		SSL_write(ssl,"Login success!!!\n",30);
		return 1;
	}
	SSL_write(ssl,"Authentication error!!!\n",30);
	return 0;
}

struct tun_route{
	pid_t pid;    //子进程pid，用来判断子进程是否已经结束，如果结束，需要释放此数据结构的内存
	unsigned int client_ip;  ////客户端使用的tun的ip地址，用来标识父进程发送给那个子进程的管道
	int fd[2];  ////管道的fd
	struct tun_route* next;  //指向下一个链表，动态行为所必须的
};

struct tun_route* tunfd_route=NULL;


void *get_tunfd(void *tunfd_1){
	int tunfd = *((int *)tunfd_1);
	int  len;
	char buff[BUFF_SIZE];
	while(1){
		bzero(buff, BUFF_SIZE);
		len = read(tunfd, buff, BUFF_SIZE);
		printf("Got a packet from server TUN\n");
		/*int i =0 ;
		for(i=0;i<len;i++){
			printf("%2x ",buff[i]);
		}*/
		struct iphdr *ip_header = (struct iphdr *)buff; 
		unsigned int src_ip = (unsigned int)ip_header->saddr;
		unsigned int dest_ip = (unsigned int)ip_header->daddr;
		printf("route dest ip:%x\n",dest_ip);
		struct tun_route* temp = tunfd_route;
		while(temp!=NULL){
			if(temp->client_ip==dest_ip){
				write(temp->fd[1], buff, len);
				break;
			}
			temp = temp->next;
		}
	}
}

void free_malloc(){
	int status;
	pid_t ret;
	struct tun_route* temp = tunfd_route;
	struct tun_route* temp2;
	if(temp!=NULL){
		if(waitpid(temp->pid,&status,WNOHANG|WUNTRACED|WCONTINUED)!=0){
			tunfd_route = temp->next;
			free(temp);
		}
		while(temp->next!=NULL){
			ret = waitpid(temp->next->pid,&status,WNOHANG|WUNTRACED|WCONTINUED);
			if(ret != 0){
				temp2 = temp->next->next;
				free(temp->next);
				temp->next =temp2;
			}
		}
	}
}


int main(int argc, char * argv[]) {
	SSL_METHOD *meth;
	SSL_CTX* ctx;
	SSL *ssl;
	int err;

	// Step 0: OpenSSL library initialization 
	// This step is no longer needed as of version 1.1.0.
	SSL_library_init();
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	// Step 1: SSL context initialization
	meth = (SSL_METHOD *)TLSv1_2_method();
	ctx = SSL_CTX_new(meth);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	// Step 2: Set up the server certificate and private key
	SSL_CTX_use_certificate_file(ctx, "./cert_server/server.crt", SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(ctx, "./cert_server/server.key", SSL_FILETYPE_PEM);
	// Step 3: Create a new SSL structure for a connection
	ssl = SSL_new(ctx);
	int tunfd, sockfd;
	tunfd = createTunDevice();
	int listen_sock = initTCPServer();
	struct sockaddr_in sa_client;
	size_t client_len;
	
	pthread_t t;
	if(pthread_create(&t, NULL, get_tunfd, (void *)(&tunfd))==-1){
		printf("pthread create dispath");
	}
	
	while (1) {
		sockfd = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);
		free_malloc();  //查询是否有子进程已经结束，如果结束，释放tun_route内存
		// 为此连接创建一个struct结构，来存储其信息
		struct tun_route* temp=tunfd_route;
		if(temp!=NULL){
			while(temp->next!=NULL){
				temp = temp->next;
			}
			temp->next = (struct tun_route*)malloc(sizeof(struct tun_route));
			temp = temp->next;
		}else{
			tunfd_route=temp= (struct tun_route*)malloc(sizeof(struct tun_route));
		}
		pipe(temp->fd);
		temp->next = NULL;
		
		if ((temp->pid = fork())==0) { // The child process
			close(listen_sock);
			

			SSL_set_fd(ssl, sockfd);

			err = SSL_accept(ssl);
			if ( err != 1 ) {
				int err_SSL_get_error = SSL_get_error(ssl, err);
				int err_ERR_get_error = ERR_get_error();
				printf("[DEBUG] SSL_accept() : Failed with return %d\n", err );
				printf("[DEBUG]     SSL_get_error() returned : %d\n",err_SSL_get_error);
				printf("[DEBUG]     Error string : %s\n",ERR_error_string( err_SSL_get_error, NULL));
				printf("[DEBUG]     ERR_get_error() returned : %d\n",err_ERR_get_error);
			}
			CHK_SSL(err);
			printf("SSL connection established!\n");

			// -----login-----
			int login = Authentication(ssl,temp->fd);

			// Enter the main loop
			while (login & 1) {
				fd_set readFDSet;

				FD_ZERO(&readFDSet);
				FD_SET(SSL_get_fd(ssl), &readFDSet);
				FD_SET(temp->fd[0], &readFDSet);
				select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

				if (FD_ISSET(SSL_get_fd(ssl), &readFDSet))
					if(socketSelected(tunfd, ssl)== 0){
						break;  //the socket is broken
					}
				if (FD_ISSET(temp->fd[0], &readFDSet)) tunSelected(temp->fd[0], ssl);
			}

			SSL_shutdown(ssl);
			SSL_free(ssl);
			close(sockfd);
			return 0;
		}
		else {
			read(temp->fd[0],&(temp->client_ip),sizeof(int));
			close(temp->fd[0]);
			close(sockfd);
		}
	}
	return 0;
}
