import scapy.all as scapy
"""
install: https://npcap.com/#download

"""
# request = scapy.ARP()
# print(request.summary())


# print()
# print(request.show())

# print()
# print(scapy.ls(scapy.ARP()))

import scapy.all as scapy

request = scapy.ARP()

# find on ipconfig
request.pdst = '192.168.1.0/24'
broadcast = scapy.Ether()

broadcast.dst = 'ff:ff:ff:ff:ff:ff'

request_broadcast = broadcast / request
clients = scapy.srp(request_broadcast, timeout = 1)[0]
for element in clients:
    print(element[1].psrc + "      " + element[1].hwsrc)

#       IPv4 Address. . . . . . . . . . . : 192.168.1.90
#    Subnet Mask . . . . . . . . . . . : 255.255.255.0