/******************************
 * Code in Chapter 15
 ******************************/


/**********************************************
 * Configuration on Pages 290-291 (Section 15.3.3)
 **********************************************/

// Step 1:
zone "example.net" {
        type master;
        file "/etc/bind/example.net.db";
      };

zone "0.168.192.in-addr.arpa" {
        type master;
        file "/etc/bind/192.168.0.db";
      };


// Step 2:
$TTL 3D ; default expiration time of all resource records without
        :   their own TTL
@       IN      SOA     ns.example.net. admin.example.net. (
        1               ; Serial
        8H              ; Refresh 
        2H              ; Retry
        4W              ; Expire
        1D )            ; Minimum

@       IN      NS      ns.example.net.       ;Address of nameserver
@       IN      MX      10 mail.example.net.  ;Primary Mail Exchanger

www     IN      A       192.168.0.101   ;Address of www.example.net
mail    IN      A       192.168.0.102   ;Address of mail.example.net
ns      IN      A       192.168.0.10    ;Address of ns.example.net
*.example.net. IN A     192.168.0.100   ;Address for other URL in
                                        ;  the example.net domain
// Step 3:
$TTL 3D
@       IN      SOA     ns.example.net. admin.example.net. (
                1
                8H
                2H
                4W
                1D)
@       IN      NS      ns.example.net.

101     IN      PTR     www.example.net.
102     IN      PTR     mail.example.net.
10      IN      PTR     ns.example.net.




/**********************************************
 * Commands on Page 295 (Section 15.5)
 **********************************************/

$ sudo netwox 105 --hostname www.example.net 
     --hostnameip 10.20.30.40 --authns ns.example.net 
     --authnsip 10.20.30.50 --filter src host 10.0.2.16
     --ttl 19000 --spoofip raw

