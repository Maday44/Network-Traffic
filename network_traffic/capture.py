import queue
import threading
from scapy.all import sniff, get_working_ifaces, conf
from parser import parse_packet
from data import PacketData


class PacketCapturer:
    def __init__(self, bpf=None):
        self.packet_queue = queue.Queue()
        self.storage = PacketData()
        self.bpf = bpf
        self.iface = self._detect_interface()
        self._running = False

    def _detect_interface(self):
        try:
            return next(
                i
                for i in get_working_ifaces()
                if i.ip and i.ip != "127.0.0.1" and not i.ip.startswith("169.254")
            )
        except StopIteration:
            return conf.iface

    def _worker(self):
        while self._running or not self.packet_queue.empty():
            try:
                parsed_packet = self.packet_queue.get(timeout=1)
                self.storage.save_packet(parsed_packet)
                print(
                    f"({parsed_packet.protocol}) "
                    f"{parsed_packet.src_ip}:{parsed_packet.src_port} >>> "
                    f"{parsed_packet.dst_ip}:{parsed_packet.dst_port} "
                    f"({parsed_packet.packet_size} bytes)"
                )
                self.packet_queue.task_done()
            except queue.Empty:
                continue

    def _packet_callback(self, pkt):
        parsed = parse_packet(pkt)
        self.packet_queue.put(parsed)

    def start_capture(self, count=20):
        self._running = True
        worker_thread = threading.Thread(target=self._worker, daemon=True)
        worker_thread.start()

        filter_str = f" [filter: '{self.bpf}']" if self.bpf else ""
        print(
            f"Starting capture on {self.iface.name} ({self.iface.ip}){filter_str}......."
        )

        # Scapy using BPF filter
        sniff(
            iface=self.iface,
            prn=self._packet_callback,
            filter=self.bpf,
            store=0,
            count=count,
        )

        self._running = False
        self.packet_queue.join()
        print("Capture completed and saved to database.")

    def stop(self):
        self._running = False
