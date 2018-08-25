#ARP Packet Sniffer
from scapy.all import *
 
def sniffer(pkt):
    if pkt[ARP].op == 1: #who-has (request)
        return 'Request: {} is asking about {}'.format(pkt[ARP].psrc, pkt[ARP].pdst)
    if pkt[ARP].op == 2: #is-at (response)
        return '*Response: {} has address {}'.format(pkt[ARP].hwsrc, pkt[ARP].psrc)
 
sniff(prn=sniffer, filter="arp")
