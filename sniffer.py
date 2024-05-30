from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print(f"TCP Packet: {src_ip}:{src_port} --> {dst_ip}:{dst_port}")

sniff(prn=packet_callback, store=0)
