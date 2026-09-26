from dataclasses import dataclass
from typing import Optional
from scapy.all import sniff, get_working_ifaces, IP, IPv6, TCP, UDP, ARP

@dataclass(frozen=True)
class ParsedPacket:
    timestamp: float
    packet_size: int 
    protocol: str 
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    version: Optional[int] = None
    ip_id: Optional[int] = None
    ttl: Optional[int] = None
    chksum: Optional[str] = None
    ack: Optional[str] = None


def parse_packet(pkt) -> ParsedPacket:
    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None
    protocol = "Ethernet"
    version = None
    ip_id = None
    ttl = None
    chksum = None
    ack = None

    # IP Layer
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        protocol = "IPv4"
        version = pkt[IP].version
        ip_id = pkt[IP].id
        ttl = pkt[IP].ttl
        chksum = hex(pkt[IP].chksum)
    elif pkt.haslayer(IPv6):
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst
        protocol = "IPv6"
        version = pkt[IPv6].version
        ttl = pkt[IPv6].hlim
    elif pkt.haslayer(ARP):
        src_ip = pkt[ARP].psrc
        dst_ip = pkt[ARP].pdst
        protocol = "ARP"

    # Transport Layer
    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        protocol = "TCP"
        chksum = hex(pkt[TCP].chksum)
        ack = str(pkt[TCP].ack)
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        protocol = "UDP"
        chksum = hex(pkt[UDP].chksum)

    return ParsedPacket(
        timestamp=float(pkt.time),
        packet_size=len(pkt),
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        version=version,
        ip_id=ip_id,
        ttl=ttl,
        chksum=chksum,
        ack=ack
    )