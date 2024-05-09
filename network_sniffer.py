from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {proto}")

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            seq = packet[TCP].seq
            ack = packet[TCP].ack
            print(f"Source Port: {src_port}, Destination Port: {dst_port}, Seq: {seq}, Ack: {ack}")

        if packet.haslayer(Raw):
            load = packet[Raw].load
            print(f"Payload: {load}")
        print("=" * 50)

sniff(prn=packet_callback, filter="tcp", count=10)

