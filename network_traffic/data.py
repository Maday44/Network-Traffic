import sqlite3
from collections import deque
from parser import ParsedPacket


class PacketData:
    def __init__(self, db_name="packets.db", max_memory_items=1000):
        self.memory_buffer = deque(maxlen=max_memory_items)
        self.db_name = db_name
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS captured_packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    packet_size INTEGER,
                    protocol TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    ttl INTEGER
                )
            """)
            conn.commit()

    def save_packet(self, parsed: ParsedPacket):
        # memory buffer
        self.memory_buffer.append(parsed)

        # saved to sql lite dB
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO captured_packets 
                (timestamp, packet_size, protocol, src_ip, dst_ip, src_port, dst_port, ttl)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    parsed.timestamp,
                    parsed.packet_size,
                    parsed.protocol,
                    parsed.src_ip,
                    parsed.dst_ip,
                    parsed.src_port,
                    parsed.dst_port,
                    parsed.ttl,
                ),
            )
            conn.commit()
