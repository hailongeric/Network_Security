all: 
	gcc -o vpn_tls_client vpn_tls_client.c -lssl -lcrypto 
	gcc -o vpn_tls_server vpn_tls_server.c -lssl -lcrypt -lcrypto -pthread

clean: 
	rm vpn_tls_client vpn_tls_server

