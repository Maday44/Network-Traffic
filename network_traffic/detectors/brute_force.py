"""
The Threat Concept: An attacker hammering a specific service (like SSH on port 22 or RDP on port 3389)
trying to gain access. In TCP terms, establishing a connection starts with a SYN packet,
followed by a SYN-ACK from the target, and an ACK from the client. 
Rapid TCP SYN flags without corresponding ACK responses indicate half-open connections or 
aggressive connection floods.

Data You Need: src_ip, dst_ip, dst_port, ack, protocol.
"""