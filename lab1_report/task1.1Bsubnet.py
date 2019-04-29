from scapy.all import *

def print_pkt(pkt):
	pkt.show()

pkt = sniff(filter='src net 202.120.224',prn=print_pkt)
