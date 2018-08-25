from scapy.all import *

def sniffer(pkt):
	'''Printing only Source and Destination IP Address'''
	print("Source IP:%s <----> Dest IP: %s" %(pkt[IP].src,pkt[IP].dst))

sniff(filter='tcp', count=100, prn=sniffer)

