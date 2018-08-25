#Scapy with Interactive Environment Style in Python
from scapy.all import *

a = sniff(filter='tcp port 80', count=10)

for i in range(10):
	a[i].show()
