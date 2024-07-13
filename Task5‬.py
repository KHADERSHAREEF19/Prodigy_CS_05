#network packet analyzer

from scapy.all import sniff, IP, TCP, UDP, ARP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = None

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ARP in packet:
            protocol =  "ARP"

        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {protocol}")
        if protocol == "TCP" or protocol == "UDP":
            print(f"payload: {bytes(packet[protocol].payload)}")
        print("-"*50)

def start_sniffing(interface):
    print(f"[*] Starting packet sniffing on interface: {interface}")
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    interface = "Wi-Fi"
    start_sniffing(interface)