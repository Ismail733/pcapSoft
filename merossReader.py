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
        if packet.haslayer(IP) and packet[IP].src == source_address and packet[IP].dst == destination_address:
            # Packet information dictionary
            packet_info = {
                "summary": packet.summary(),
                "details": packet.show(dump=True)
            }
            packet_info_list.append(packet_info)

# Write packet information to a JSON file
output_file = 'packet_info.json'
with open(output_file, 'w') as json_file:
    json.dump(packet_info_list, json_file, indent=4)

print(f"Packets information saved to {output_file}")
