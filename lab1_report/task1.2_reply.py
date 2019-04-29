from scapy.all import *


def print_pkt(pkt):
    # print(pkt[IP].src)
    # pkt.show()
    if pkt[ICMP].type == 8:
        pkt[ICMP].type = 0
        dstIP =  pkt[IP].src
        pkt[IP].src = pkt[IP].dst
        pkt[IP].dst = dstIP
        a = IP(pkt[IP])
        b = ICMP(pkt[ICMP])
        send(a / b)


def recICMP():
    pkt = sniff(filter='icmp', prn=print_pkt)


def main():
    recICMP()

if __name__ == '__main__':
    main()
