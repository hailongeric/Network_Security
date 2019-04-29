from scapy.all import *
from threading import Thread
import time

def sendICMP():
    global destIp
    global controlkey
    global number
    global start

    a = IP()
    a.dst=destIp
    b = ICMP()
    while controlkey == True:
        controlkey = False
        a.ttl = number
        number = number + 1
        send(a / b)
        start = time.time()
        semaphore2.release()
        semaphore1.acquire()
    # route_file = open('temp.txt','r')
    # print(route_file.read())
    # route_file.close()




def print_pkt(pkt):
    global destIp
    global controlkey
    global number
    global start
    # global temp_file
    global this

    if this == True and pkt[IP].src == destIp:
        # temp_file.write(str(number - 1) + "       " + pkt[IP].src+'\n')
        # temp_file.close()
        this = False
        print(str(number - 1) + "    " + pkt[IP].src)
        semaphore1.release()
        return
    if this == True and pkt[IP].proto == 1 and pkt[ICMP].type == 11:
        semaphore2.acquire()
        # temp_file.write(str(number - 1) + "        " + pkt[IP].src + '\n')
        print(str(number-1) + "    " + pkt[IP].src)
        controlkey = True
        semaphore1.release()
    else:
        if this == True  and time.time()-start > 2:
            semaphore2.acquire()
            # temp_file.write(str(number - 1) + "        " + "****" + '\n')
            print(str(number-1) + "     " + "****")
            controlkey = True
            semaphore1.release()


def recICMP():
    pkt = sniff(filter='ip', prn=print_pkt)



destIp = ''
# controlkey control if sending pkt or not
controlkey = True
# this is ttl
number = 1
# this is to deal with out of time
start = time.time()
# the file is to deal with printing orderly and neatly
# temp_file = open('temp.txt','w')
# temp_file.write('\nnumber     route\n')
semaphore1 = threading.Semaphore(0)
semaphore2 = threading.Semaphore(0)
#  judge if process is over or not by 'this'
this = True

def main():
    global destIp
    destIp = raw_input('Please input destination IP:')
    tr = Thread(target=sendICMP)
    ts = Thread(target=recICMP)

    tr.start()
    ts.start()

    tr.join()
    ts.join()


if __name__ == '__main__':
    main()
