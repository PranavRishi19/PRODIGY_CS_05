from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Extracting relevant packet information
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        if protocol == 6:  # TCP
            proto_str = "TCP"
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            else:
                src_port = dst_port = "N/A"
        elif protocol == 17:  # UDP
            proto_str = "UDP"
            if UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            else:
                src_port = dst_port = "N/A"
        elif protocol == 1:  # ICMP
            proto_str = "ICMP"
            src_port = dst_port = "N/A"
        else:
            proto_str = "Other"
            src_port = dst_port = "N/A"

        print(f"IP Packet: {ip_src} -> {ip_dst} | Protocol: {proto_str} | Src Port: {src_port} | Dst Port: {dst_port}")
    else:
        print("Non-IP Packet")

def main():
    # Capturing packets
    print("Starting packet capture. Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
