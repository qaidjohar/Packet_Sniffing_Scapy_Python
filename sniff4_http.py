from scapy.all import *

def sniffer(packet):
	'''Printing only SRC IP and Dst IP, Dst Port, Payload'''
	if packet[IP].dport == 80:
		print("\n{} ----HTTP----> {}:{}:\n{}".format(packet[IP].src, packet[IP].dst, packet[IP].dport, str(bytes(packet[TCP].payload))))

sniff(filter='tcp port 80', prn=sniffer)

