## VPN and Bypassing Firewalls using VPN Lab Report

> Host U 10.0.2.4   Host V  192.168.60.101  Gateway  enp0s3: 10.0.2.5 enp0s8:192.168.60.1     Host U： tun0 192.168.53.5   VPN Server tun0:192.168.53.1 

### Task1: VM Setup 

因为在vpn server和 host V之间设置的是Internal Network网络，所以我们需要给VPN server的Internal Network网卡和host V 配置DHCP（动态主机设置协议），示例如下图：

![1544098702610](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544098702610.png)

### Task2: Creating a VPN Tunnel using TUN/TAP

#### Step 1: Run VPN Server.

启动虚拟网卡并给它配置IP地址后，证据如图所示：

![1544098544220](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544098544220.png)

#### Step 2: Run VPN Client.

观察给的代码，发现将其连接IP设成127.0.0.1，与文档稍有差别，所以将其改为VPN server的外部连接地址10.0.2.5，运行程序，挂上IP后，显示结果：

![1544099623730](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544099623730.png)

![1544098381350](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544098381350.png)

#### Step 3: Set Up Routing on Client and Server VM

使用相关命令设置路由表项结果如下：

![1544097548419](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544097548419.png)

![1544097564495](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544097564495.png)

#### Step 4: Set Up Routing on Host V.

在host V 让其将从host U 来的报文转发到VPN服务器上，其实不需要这个命令也可以，因为外部网络的链接必定通过网关路由器。host V 命令： 

``` 
sudo route add -net 192.168.53.0/24 gw 192.168.60.1 dev enp0s3
```

![1544097580904](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544097580904.png)

#### Step 5: Test the VPN Tunnel

ping和telnet结果：

![1544096849219](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544096849219.png)

在主机U上抓取的报文：

![1544096604011](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544096604011.png)

数据包1：由ping命令生成。 由于路由设置，ICMP数据包被路由到TUN接口（目的IP为192.168.60.0/24->分配给tun0的原因）
数据包2：隧道应用程序获取ICMP数据包，然后将其提供给其隧道 - >将其放入UDP数据包中，朝向VPN服务器（10.0.2.5）。
数据包No 3：来自VPN Server->的返回UDP数据包是来自192.168.60.101的封装ICMP回应数据包
数据包No 4：VPN Client上的隧道应用程序获取此UDP数据包，并取出封装的ICMP数据包，并通过tun0接口将其提供给内核。
数据包No 5到8：由另一个ICMP回应请求消息触发。

telnet解释通上：

![1544096706622](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544096706622.png)

#### Step6: Tunnel-Breaking Test.

当使用命令：

```
sudo ifconfig tun0 192.168.53.1/24 down
```

将通道断了之后，发现telnet完全没反应了，观察流量包：

![1544101681096](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544101681096.png)

说明telnet仍在工作，但由于它通过损坏的VPN隧道发送的数据包不在任何地方，TCP将继续重新发送数据包。
VPN Server将丢弃UDP数据包并发回ICMP错误消息，告知VPN客户端端口不可访问。 这就是我们看到多个ICMP错误消息的原因。

当重新使用命令：

```
sudo ifconfig tun0 192.168.53.1/24 up
```

后，观察流量包以及显示屏，发现又可以正常化使用连接：

![1544102075966](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544102075966.png)

![1544102103666](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544102103666.png)

无论输入到telnet中的是什么都没有丢失，它们被缓冲，等待发送到telnet服务器。

### Task3: Encrypting the Tunnel 

首先，在host U上/etc/hosts 中 加入：

```
10.0.2.5        vpnlabserver.com
```

然后根据readme的指导，进行测试，获取的报文如下：

![1544103051217](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544103051217.png)

一个完成的TLS握手协议，client hello 以及 server hello，完成了各个参数，加密算法验证算法等的确认，以及改变加密方式格式，是一个完成的TLS传输过程，当握手过程完成，密钥协商完成后，使用对称加密方式传输数据，使其所有的信息都加密传输：

因为是TCP传输通道，所以比上面的UDP通道相比每次都有一个ACK确认。

![1544146441600](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544146441600.png)

![1544103359542](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544103359542.png)

###  Task4: Authenticating the VPN Server 

> 说明，我的自签名证书Eric_hailong( cert.pem ), 然后使用它给服务器签名Hailong.com (server.crt)，客户端的签名证书EricHailong.client.com(client.crt)，所有的密钥访问密码都是1234567890

首先，所有的验证都在TLS handshake阶段完成，主要函数都封装在SSL句柄里面，对于证书的认证，由函数SSL_CTX_set_verify处理，根据TLS协议，证书无效会立即断掉TLS握手过程，其他的认证都集中在SSL的句柄中，其中主机名称的认证，在函数X509_VERIFY_PARAM_set1_host中。验证服务器拥有它，在函数SSL_CTX_set_verify中，通过服务器的数字签名进行验证，而函数SSL_CTX_load_verify_locations只是设置验证证书有效性的本地根证书之一。

```
SSL* setupTLSClient(const char* hostname) {
	...
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
	if (SSL_CTX_load_verify_locations(ctx, NULL, CA_DIR) < 1) {
		printf("Error setting the verify locations. \n");
		exit(0);
	}
	ssl = SSL_new(ctx);
	X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
	X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);
	...
}
```

我们可以通过回调函数，可以打印主机名称认证的过程，在这里SSL通过回调函数，将结果返回给我们，决定权在我们手中，如下图：即是认证没有通过，我们任然可以进行通信：

![1544203736729](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544203736729.png)

在这里，回调函数并没有因验证失败而exit()掉，只是将信息打印了出来：

```
int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx){
...
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
```



成功的实例：

![1544203286646](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544203286646.png)

### Task5: Authenticating the VPN Client

 在SSL建立完成后，在客户端安全发送用户名和密码，然后服务端进行验证，代码：

```
	// 格式 sudo ./vpn_tls_client hailong:xxx@Hailong.com 	
	if (argc > 1&&strchr(argv[1],':')!=NULL&&strchr(argv[1],'@')!=NULL){
		i = (size_t)(strchr(argv[1],':')-argv[1]);
		j = (size_t)(strchr(argv[1],'@')-argv[1]);
		bzero(user, 12);
		bzero(passwd, 12);
		strncpy(user,argv[1],i);
		strncpy(passwd,argv[1]+i+1,j-i-1);
	}
	.....
		
	// -----login-----
	char buff[30];
	bzero(buff, 30);
	strncpy(buff, user, strlen(user));
	strncpy(buff+12, passwd, strlen(passwd));
	SSL_write(ssl, buff, 30);
	bzero(buff, 30);
	SSL_read(ssl, buff, sizeof(buff) - 1);
	printf("%s", buff);
```

客户端验证代码：

```
int login = Authentication(ssl);	
	while (login&1) {
.....
```

结果截图：

服务器端：（为了测试，打印出了用户名和密码）

![1544617906826](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544617906826.png)

客户端：

![1544617972406](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544617972406.png)

### Task6: Supporting Multiple Clients 

此程序我使用的是文档所指导的使用fork函数为每一个vpn连接创建一个子进程的方法完成的。

思路：为每个client做个标识，当数据从tun来之后，根据唯一的标识使用pipe发送给子进程，然后就如一个连接的方法一样进行处理。

细节：首先，我在主函数里面使用一个数据结构来区分每个连接：

```
struct tun_route{
	pid_t pid;    //子进程pid，用来判断子进程是否已经结束，如果结束，需要释放此数据结构的内存
	unsigned int client_ip; //客户端使用的tun的ip地址，用来标识父进程发送给那个子进程的管道
	int fd[2];  //管道的fd
	struct tun_route* next;  //指向下一个链表，动态行为所必须的
};
```

主函数：

```
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
	//在父进程中创建一个线程，用来一直检测tun是否有数据到达，进行tun数据的路由转发
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
		//建立管道
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
						break;  //如果通道断开，需要结束此子进程
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
```

由于客户端的tunIP在TLS连接建立后才确认的，所以在 Authentication函数里面加了一个从子进程向父进程通知client_ip标识号的代码。因为区域ip是由服务器分配的，所以在客户端进行登录时，需要提供自己的tunIP,这一点其实可以通过服务器动态分配发送一个区域网的IP给客户端，在客户端代码里面可以使用system()函数自动配置自己的tunX网卡，不用手动配置。

由于电脑的问题，所以我并没有使用4台虚拟机数据提供证明，为了证明程序的正确性，我在主机U上开启了两个VPN连接：

![1545219708623](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1545219708623.png)

为了证明正确性，我在主机U上配置不同的route:

![1545219780469](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1545219780469.png)

其中虚拟网卡tun1的IP是192.168.53.6.然后在主机U上使用ping 进行ping这两个IP。观察wireshark抓包：

![1545220021037](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1545220021037.png)

发现，ping的结果通过通道正确传过来了，（由于我在服务端没有额外配置，所以是无法访问外网）。

观察server端的信息：

![1545220180570](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1545220180570.png)

能够正确区分不同的routeIp.

接着断掉192.168.53.5的连接，观察运行状态，发现：

![1545220283991](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1545220283991.png)

发现完全可以正确运行，

![1545220324210](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1545220324210.png)

说明此程序在用户的连接与用户的离开，等路由机制完全正确。

#### 说明

客户端

```
$make
$sudo ./vpn_tls_client seed:dees@Hailong.com 192.168.53.5
```

服务端

```
$make
$sudo ./vpn_tls_server 
$需要输入证书私钥pem的读取密码：1234567890
$sudo ifconfig tun0 192.168.53.1/24 up
```



## Firewall Evasion Lab: Bypassing Firewalls using VPN

### Task1: VM Setup  

前面实验已经完成

### Task2: Setup Firewall

 ![1544626386416](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544626386416.png)

使用www.baidu.com测试，如前面实验所做，可以发现当启用防火墙后，将119.75.217.0/24子网拒绝后，可以发现，百度无法访问。

###  Task3: Bypassing Firewall using VPN 

#### Step 1: Run VPN Server. 

前面已经完成

#### Step 2: Run VPN Client. 

前面已经完成

#### Step3: SetUp Routing on Client and Server VMs

命令：在客户端将所有的流量转发到VPN管道中，或者把被防火墙所阻挡得流量转发到VPN通道中。

```
sudo route add -net default dev tun0
```

在服务端的设置：

![1545223714112](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1545223714112.png)

需要注意，把默认第一个网卡enp0s8删掉。因为是内网网卡。

#### Step 4: Set Up NAT on Server VM. 

 When the ﬁnal destination sends packets back to users, the packet will be sent to the VPN Server ﬁrst (think about why and write down your answer in the report). 

因为当客户端得报文到了服务器后，里面的报文源IP地址是服务器局域网中的一个IP地址，当服务器转发后，相当于服务器局域网中的主机发送的报文，所以，报文回复后，直接来的服务器的局域网中，又因为VPN服务器是一个网关，所以它决定了此IP地址转发方向。

telnet连接：

![1545223843006](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1545223843006.png)

数据包：

![1545223856015](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1545223856015.png)

网络访问：

![1545224460846](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1545224460846.png)

数据包：

![1545223884848](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1545223884848.png)





