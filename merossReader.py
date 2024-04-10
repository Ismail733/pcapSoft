from scapy.all import *
import json

class MerossAnalyzer:
    def __init__(self, file_path, source_address, destination_address):
        self.file_path = file_path
        self.source_address = source_address
        self.destination_address = destination_address
        self.packet_info_list = []

    def analyze_packets(self):
        with PcapReader(self.file_path) as pcap_reader:
            for packet in pcap_reader:
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst

                if (src_mac == self.source_address or src_mac == self.destination_address) and (dst_mac == self.source_address or dst_mac == self.destination_address):
                    ethernet_info = {
                        "src_mac": src_mac,
                        "dst_mac": dst_mac
                    }

                    ip_info = {}
                    if IP in packet:
                        ip_info = {
                            "src_ip": packet[IP].src,
                            "dst_ip": packet[IP].dst
                        }

                    tcp_info = {}
                    if TCP in packet:
                        tcp_info = {
                            "src_port": packet[TCP].sport,
                            "dst_port": packet[TCP].dport
                        }

                    # Check if Raw layer exists and it's not empty
                    if Raw in packet and packet[Raw].load:
                        try:
                            payload = json.loads(packet[Raw].load.decode('utf-8'))
                        except json.JSONDecodeError:
                            payload = packet[Raw].load.decode('utf-8')
                    else:
                        payload = None

                    if payload is not None:  # Discard packets with no payload
                        packet_info = {
                            "ethernet": ethernet_info,
                            "ip": ip_info,
                            "tcp": tcp_info,
                            "payload": payload
                        }
                        self.packet_info_list.append(packet_info)

    def save_to_json(self, output_file):
        with open(output_file, 'w') as json_file:
            json.dump(self.packet_info_list, json_file, indent=4)
        print(f"Packets information saved to {output_file}")

# Usage
file_path = '2_meross_on_off.pcapng'
source_address = 'aa:f9:24:38:27:e1'
destination_address = '48:e1:e9:3a:3a:b7'
output_file = 'packet_info.json'

analyzer = MerossAnalyzer(file_path, source_address, destination_address)
analyzer.analyze_packets()
analyzer.save_to_json(output_file)
