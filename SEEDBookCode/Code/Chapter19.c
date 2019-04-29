/******************************
 * Code in Chapter 19
 ******************************/



/**********************************************
 * Listing 19.1: setupTLSClient()
 **********************************************/

SSL* setupTLSClient(const char* hostname)
{
   // Step 0: OpenSSL library initialization 
   // This step is no longer needed as of version 1.1.0.
   SSL_library_init();
   SSL_load_error_strings();

   // Step 1: SSL context initialization
   SSL_METHOD *meth = (SSL_METHOD *)TLSv1_2_method();
   SSL_CTX* ctx = SSL_CTX_new(meth);
   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
   SSL_CTX_load_verify_locations(ctx, NULL, "./cert");

   // Step 2: Create a new SSL structure for a connection
   SSL* ssl = SSL_new (ctx);

   // Step 3: Enable the hostname check
   X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
   X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

   return ssl;
}
 


/**********************************************
 * Listing 19.2: setupTCPClient()
 **********************************************/

int setupTCPClient(const char* hostname, int port)
{
   struct sockaddr_in server_addr;

   // Get the IP address from hostname
   struct hostent* hp = gethostbyname(hostname);

   // Create a TCP socket
   int sockfd= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

   // Fill in the destination information (IP, port #, and family)
   memset (&server_addr, '\0', sizeof(server_addr));
   memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
   server_addr.sin_port   = htons (port);
   server_addr.sin_family = AF_INET;

   // Connect to the destination
   connect(sockfd, (struct sockaddr*) &server_addr, 
           sizeof(server_addr));

   return sockfd;
}



/**********************************************
 * Listing 19.3: Start TLS Handshake
 **********************************************/

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); 
                                      exit(2); }

SSL* ssl = setupTLSClient(hostname);          // See Listing 19.1
int  sockfd = setupTCPClient(hostname, port); // See Listing 19.2

SSL_set_fd(ssl, sockfd);
int err = SSL_connect(ssl); 
CHK_SSL(err);

printf("SSL connection is successful\n");
printf ("SSL connection using %s\n", SSL_get_cipher(ssl));



/**********************************************
 * Listing 19.4: Read and send data
 **********************************************/

char buf[9000];
char sendBuf[200];

sprintf(sendBuf, "GET / HTTP/1.1\nHost: %s\n\n", hostname);
SSL_write(ssl, sendBuf, strlen(sendBuf));

int len;
do {
     len = SSL_read (ssl, buf, sizeof(buf) - 1);
     buf[len] = '\0';
     printf("%s\n",buf);
} while (len > 0);



/**********************************************
 * Listing 19.5: The complete TLS client code
 **********************************************/

#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <netdb.h>

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); 
                                      exit(2); }

SSL* setupTLSClient(const char* hostname) { ... } 
int setupTCPClient(const char* hostname, int port) { ... }

int main(int argc, char *argv[])
{
   char *hostname = "example.com";
   int port = 443;

   if (argc > 1) hostname = argv[1];
   if (argc > 2) port = atoi(argv[2]);

   /*----------------TLS initialization ----------------*/
   SSL *ssl   = setupTLSClient(hostname);

   /*----------------Create a TCP connection ---------------*/
   int sockfd = setupTCPClient(hostname, port);

   /*----------------TLS handshake ---------------------*/
   SSL_set_fd(ssl, sockfd);
   int err = SSL_connect(ssl); CHK_SSL(err);
   printf("SSL connection is successful\n");
   printf ("SSL connection using %s\n", SSL_get_cipher(ssl));

   /*----------------Send/Receive data --------------------*/
   char buf[9000];
   char sendBuf[200];

   sprintf(sendBuf, "GET / HTTP/1.1\nHost: %s\n\n", hostname);
   SSL_write(ssl, sendBuf, strlen(sendBuf));

   int len;
   do {
     len = SSL_read (ssl, buf, sizeof(buf) - 1);
     buf[len] = '\0';
     printf("%s\n",buf);
   } while (len > 0);
}



/**********************************************
 * Listing 19.6: Modified TLS setup code
 **********************************************/

SSL* setupTLSClient(const char* hostname)
{
   SSL_METHOD *meth;
   SSL_CTX* ctx;
   SSL* ssl;

   meth = (SSL_METHOD *)TLSv1_2_method();
   ctx = SSL_CTX_new(meth);

   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback); 
   SSL_CTX_load_verify_locations(ctx, NULL, "./cert");
   ssl = SSL_new (ctx);

   // Enable the hostname check
   X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);  
   X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

   return ssl;
}



/**********************************************
 * Listing 19.7: The callback function
 **********************************************/

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    char  buf[300];

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx); 
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("subject= %s\n", buf);     

    if (preverify_ok == 1) {
       printf("Verification passed.\n");
    } else {
       int err = X509_STORE_CTX_get_error(x509_ctx);
       printf("Verification failed: %s.\n", 
		    X509_verify_cert_error_string(err)); 
    }
}



/**********************************************
 * Listing 19.9: setupTLSServer()
 **********************************************/

SSL* setupTLSServer()
{
    SSL_METHOD *meth;
    SSL_CTX* ctx;
    SSL* ssl;
    int err;

    // Step 1: SSL context initialization
    meth = (SSL_METHOD *)TLSv1_2_method();
    ctx = SSL_CTX_new(meth);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);           

    // Step 2: Set up the server certificate and private key
    SSL_CTX_use_certificate_file(ctx, "./bank_cert.pem", 
                                 SSL_FILETYPE_PEM);           
    /* SSL_CTX_use_certificate_chain_file(ctx, 
                                 "./bank_chain_cert.pem"); */ 
    SSL_CTX_use_PrivateKey_file(ctx, "./bank_key.pem", 
                                 SSL_FILETYPE_PEM);           

   // Step 3: Create a new SSL structure for a connection
    ssl = SSL_new (ctx);

    return ssl;
}



/**********************************************
 * Listing 19.10: setupTCPServer()
 **********************************************/
 
int setupTCPServer()
{
    struct sockaddr_in sa_server;
    int listen_sock;

    listen_sock= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset (&sa_server, '\0', sizeof(sa_server));
    sa_server.sin_family      = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port        = htons (4433);
    bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
    listen(listen_sock, 5);
    return listen_sock;
}



/**********************************************
 * Listing 19.11: The main function of the TLS server code
 **********************************************/

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); 
                                      exit(2); }

SSL* setupTLSServer();                   // Defined in Listing 19.9
int  setupTCPServer();                   // Defined in Listing 19.10
void processRequest(SSL* ssl, int sock); // Defined in Listing 19.12

int main(){
  SSL* ssl        = setupTLSServer();   
  int listen_sock = setupTCPServer();  

  while (1) {
    int sock = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);
    if (fork() == 0) { // The child process
       close (listen_sock);

       SSL_set_fd (ssl, sock);
       int err = SSL_accept (ssl);
       CHK_SSL(err);
       printf ("SSL connection established!\n");

       processRequest(ssl, sock);   
       close(socket);
       return 0;
    } else { // The parent process
        close(sock);
    }
  }
}



/**********************************************
 * Listing 19.12: processRequest()
 **********************************************/

void processRequest(SSL* ssl, int sock)
{
    char buf[1024];
    int len = SSL_read (ssl, buf, sizeof(buf) - 1);
    buf[len] = '\0';
    printf("Received: %s\n",buf);

    // Construct and send the HTML page
    char *html =
"HTTP/1.1 200 OK\r\n"
"Content-Type: text/html\r\n\r\n"
"<!DOCTYPE html><html>"
"<head><title>Hello World</title></head>"
"<style>body {background-color: black}"
"h1 {font-size:3cm; text-align: center; color: white;"
"text-shadow: 0 0 3mm yellow}</style></head>"
"<body><h1>Hello, world!</h1></body></html>";
    SSL_write(ssl, html, strlen(html));
    SSL_shutdown(ssl);  SSL_free(ssl);
}


