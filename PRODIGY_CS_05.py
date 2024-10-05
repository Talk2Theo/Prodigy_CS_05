from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Function to analyze each packet captured
def packet_analysis(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"\n[+] Packet Captured: {ip_layer.src} --> {ip_layer.dst}")

        # Check for specific protocols (TCP, UDP, ICMP)
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP | Source Port: {tcp_layer.sport} | Destination Port: {tcp_layer.dport}")
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"Protocol: UDP | Source Port: {udp_layer.sport} | Destination Port: {udp_layer.dport}")
        elif packet.haslayer(ICMP):
            print(f"Protocol: ICMP")

        # Display the packet payload (if any)
        if packet.haslayer(Raw):
            print(f"Payload: {packet[Raw].load}")
        else:
            print("No payload data.")
    else:
        print("Non-IP packet detected.")

# Capture packets on the network interface
def start_sniffing(interface):
    print(f"Starting packet sniffing on {interface}...\n")
    sniff(iface=interface, prn=packet_analysis, store=False)

# Example usage
if __name__ == "__main__":
    # Replace 'eth0' with your network interface (use 'ifconfig' or 'ipconfig' to find out)
    interface = "eth0"  # For Linux, on Windows it could be 'Ethernet'
    start_sniffing(interface)
