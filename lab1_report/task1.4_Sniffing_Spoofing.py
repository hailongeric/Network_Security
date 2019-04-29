from scapy.all import *
import commands

def sendICMP(pkt):
    temp = pkt[IP].dst
    pkt[IP].dst = pkt[IP].src
    pkt[IP].src = temp
    del pkt[ICMP].chksum
    a = IP(pkt[IP])
    a[ICMP].type = 0
    del a[ICMP].chksum
    send(a)


def print_pkt(pkt):
    if pkt[ICMP].type == 8:
        sendICMP(pkt)


def recICMP():
    pkt = sniff(filter='icmp', prn=print_pkt)

def main():
    recICMP()

if __name__ == '__main__':
    main()
