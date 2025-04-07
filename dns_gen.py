from scapy.all import *

pkt = (Ether()/IP(dst="fc00:dead:cafe:1::1")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com")))
sendp(pkt, iface="veth-dns")
