from scapy.all import *


def sendICMP():
	a = IP()
	a.dst = raw_input('Please Input destination Address:')
	a.src = raw_input('Please Input source Address:')
	b = ICMP()
	b.type = 8
        b.ttl = 128
        send(a / b)


def main():
    sendICMP()

if __name__ == '__main__':
    main()
