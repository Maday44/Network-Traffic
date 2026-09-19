from dataclasses import dataclass
from typing import Optional
from scapy.all import sniff, get_working_ifaces, IP, IPv6, TCP, UDP, ARP, Ether

@dataclass(frozen=True)
class ParsedPacket:
    timestamp: float
    packet_size: int 
    protocol: str  
    src_ip: str 
    dst_ip: str  
    src_port: int
    dst_port: int
    version: int
    id: int
    ttl: int
    chksum: str
    ack: str



def parse_packet(pkt) -> ParsedPacket:

    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None
    protocol = "Ethernet"


    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        protocol = "IPv4"
    elif pkt.haslayer(IPv6):
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst
        protocol = "IPv6"
    elif pkt.haslayer(ARP):
        src_ip = pkt[ARP].psrc
        dst_ip = pkt[ARP].pdst
        protocol = "ARP"


    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        protocol = "TCP"
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        protocol = "UDP"


    return ParsedPacket(
        timestamp=float(pkt.time),
        packet_size=len(pkt),
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port
    )



def process_packet(pkt):
    parsed = parse_packet(pkt)
    print(parsed)



my_iface = next(i for i in get_working_ifaces() if i.index == 11)
sniff(iface=my_iface, prn=process_packet, count=10)