# Packet Sniffer

![Packet Sniffer](https://example.com/your-image-url.jpg) <!-- Replace with an actual image URL if you have one -->

## Overview

A Packet Sniffer is a tool used to capture and analyze network packets. It can be used for network troubleshooting, monitoring, and security analysis. This project demonstrates a basic implementation of a packet sniffer in Python using the `scapy` library.

## Features

- **Packet Capture**: Capture live network packets.
- **Protocol Analysis**: Analyze captured packets to determine the protocols in use.
- **Packet Filtering**: Filter packets based on specific criteria.
- **Logging**: Save captured packets to a file for later analysis.

## How It Works

The packet sniffer captures live network packets by putting the network interface into promiscuous mode. It then analyzes the packets to extract useful information such as source and destination addresses, protocols, and payload data.

### Example

Here is an example of how the packet sniffer captures and analyzes packets:

```python
from scapy.all import sniff, IP, TCP

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"[!] New Packet: {ip_layer.src} -> {ip_layer.dst}")
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            print(f"TCP Packet: {tcp_layer.sport} -> {tcp_layer.dport}")

# Sniff packets
sniff(prn=packet_callback, count=10)
