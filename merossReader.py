from scapy.all import *
import json

file_path = '2_meross_on_off.pcapng'
source_address = '10.42.0.141'
destination_address = '10.42.0.14'

# List to store packet information
packet_info_list = []

with PcapReader(file_path) as pcap_reader:
    for packet in pcap_reader:
        # Check if the packet has IP layer and matches the source and destination addresses
        if IP in packet and packet[IP].src == source_address and packet[IP].dst == destination_address:
            # Extract information from Ethernet and IP layers
            ethernet_info = {
                "src_mac": packet[Ether].src,
                "dst_mac": packet[Ether].dst
            }
            ip_info = {
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst
            }
            
            # Extract TCP information if available
            tcp_info = {}
            if TCP in packet:
                tcp_info = {
                    "src_port": packet[TCP].sport,
                    "dst_port": packet[TCP].dport
                }

            # Extract HTTP/JSON payload if present
            payload = None
            if Raw in packet:
                try:
                    payload = json.loads(packet[Raw].load.decode('utf-8'))
                except json.JSONDecodeError:
                    payload = packet[Raw].load.decode('utf-8')

            # Construct packet information dictionary
            packet_info = {
                "ethernet": ethernet_info,
                "ip": ip_info,
                "tcp": tcp_info,
                "payload": payload
            }
            packet_info_list.append(packet_info)

# Write packet information to a JSON file
output_file = 'packet_info.json'
with open(output_file, 'w') as json_file:
    json.dump(packet_info_list, json_file, indent=4)

print(f"Packets information saved to {output_file}")

