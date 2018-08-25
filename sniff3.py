from scapy.all import *

def sniffer(pkt):
	'''Printing only Source and Destination MAC Address'''
	print("Source MAC:%s <----> Dest MAC: %s" %(pkt[Ether].src,pkt[Ether].dst))

sniff(filter='tcp', prn=sniffer)

