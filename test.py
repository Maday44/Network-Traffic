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
from scapy.all import sniff, get_working_ifaces, IP

# Selects your Realtek card using its index number (11)
# scapy > show_interface > gte wirless interface on your network my one is index 11
my_iface = next(i for i in get_working_ifaces() if i.index == 11) #  long hardware GUID identifier

ip_found = 0
none_ip = 0

# def print_pkt(pkt):
#     global ip_found
#     global none_ip

#     # check if ip 
#     if pkt.haslayer(IP):
#         ip_found += 1
#         print('IP found')
#         print(pkt.summary())
#         print(f"Source: {pkt[IP].src} -> Destination: {pkt[IP].dst}")
#         print()
#     else:
#         none_ip += 1
#         print(pkt.summary())
#         print()

#     print(f"Number of IP found {ip_found}:  Number of Non-IP: {none_ip}")

# sniff(iface=my_iface, prn=print_pkt, count=10)

from scapy.all import sniff, get_working_ifaces, IP, ARP, IPv6, TCP, UDP, Ether

my_iface = next(i for i in get_working_ifaces() if i.index == 11)

stats = {
    "ipv4": 0,
    "ipv6": 0,
    "arp": 0,
    "other": 0
}

def parse_packet(pkt):
    """
    Sort the packet protocols
    """
    
    # IPv4 Traffic 32 bit adress, multiple local devices can use the same IP
    if pkt.haslayer(IP):
        stats["ipv4"] += 1
        ip_layer = pkt[IP]
        
        # Transport Layer
        if pkt.haslayer(TCP):
            proto_info = f"TCP {pkt[TCP].sport} -> {pkt[TCP].dport}"
        else:
            proto_info = f"UDP {pkt[UDP].sport} -> {pkt[UDP].dport}"

        print(f"[IPv4] {ip_layer.src} -> {ip_layer.dst} , {proto_info}")

    # IPv6 Traffic 128 bit address
    elif pkt.haslayer(IPv6):
        stats["ipv6"] += 1
        print(f"[IPv6] {pkt[IPv6].src} -> {pkt[IPv6].dst}")

    # ARP Traffic
    elif pkt.haslayer(ARP):
        stats["arp"] += 1
        arp_layer = pkt[ARP]
        op = "Request" if arp_layer.op == 1 else "Reply"
        print(f"[ARP {op}] Who has {arp_layer.pdst}? Tell {arp_layer.psrc} ({arp_layer.hwsrc})")

    # not IP or arp
    else:
        stats["other"] += 1
        summary = pkt.summary()
        # Fall back to Ethernet layer if present
        if pkt.haslayer(Ether):
            src_mac = pkt[Ether].src
            dst_mac = pkt[Ether].dst
            print(f"[Ether] {src_mac} -> {dst_mac} , {summary}")
        else:
            print(f"[OTHER] {summary}")

    print(f"Stats: {stats}\n")

# Start sniffing
sniff(iface=my_iface, prn=parse_packet, count=20)

# request = scapy.ARP()

# # find on ipconfig
# request.pdst = '192.168.1.0/24'
# broadcast = scapy.Ether()

# broadcast.dst = 'ff:ff:ff:ff:ff:ff'

# request_broadcast = broadcast / request
# clients = scapy.srp(request_broadcast, timeout = 1)[0]
# for element in clients:
#     print(element[1].psrc + "      " + element[1].hwsrc)

# #       IPV4 Address. . . . . . . . . . . : 192.168.1.90
# #    Subnet Mask . . . . . . . . . . . : 255.255.255.0


from scapy.all import ls, IP, TCP, UDP, Ether
print()
ls(IP)   # Shows all fields for the IP header (version, ihl, tos, len, id, flags, proto, src, dst, etc.)
print()
ls(TCP)  # Shows all fields for the TCP header (sport, dport, seq, ack, dataofs, flags, etc.)
print()
ls(UDP)  # Shows all fields for the UDP header (sport, dport, len, chksum)
print()
ls(Ether)# Shows all fields for the Ethernet header (dst, src, type)
