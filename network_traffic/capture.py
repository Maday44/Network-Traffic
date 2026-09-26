import queue
import threading
from scapy.all import sniff, get_working_ifaces
from parser import parse_packet
from data import PacketData

packet_queue = queue.Queue()
data = PacketData()

def packet_callback(pkt):
    parsed = parse_packet(pkt)
    packet_queue.put(parsed)

def packet_worker():
    while True:
        parsed_packet = packet_queue.get()
        if parsed_packet is None:
            break
        data.save_packet(parsed_packet)
        print(f"({parsed_packet.protocol}) {parsed_packet.src_ip}:{parsed_packet.src_port} >>> {parsed_packet.dst_ip}:{parsed_packet.dst_port}")
        packet_queue.task_done()

if __name__ == "__main__":
    worker_thread = threading.Thread(target=packet_worker, daemon=True)
    worker_thread.start()

    try:
        my_iface = next(
            i for i in get_working_ifaces() 
            if i.ip and i.ip != "127.0.0.1" and not i.ip.startswith("169.254")
        )
    except StopIteration:
        from scapy.all import conf
        my_iface = conf.iface

    print(f"Starting capture on {my_iface.name} ({my_iface.ip})............")

    # testiung 50 packets
    sniff(iface=my_iface, prn=packet_callback, store=0, count=50)
    packet_queue.join()
    print("Run 50 packets and now saved to DB.")