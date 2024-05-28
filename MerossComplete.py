from scapy.all import *
import json
import matplotlib.pyplot as plt
import time

# Usage
file_path = '2_meross_on_off.pcapng'
source_address = 'aa:f9:24:38:27:e1'
destination_address = '48:e1:e9:3a:3a:b7'
output_file = 'packet_info.json'

#From pcapng to only mss310's packet in json
class MerossAnalyzer:
    def __init__(self, file_path, source_address, destination_address):
        self.file_path = file_path
        self.source_address = source_address
        self.destination_address = destination_address
        self.packet_info_list = []

    def analyze_packets(self):
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

analyzer = MerossAnalyzer(file_path, source_address, destination_address)
analyzer.analyze_packets()

class MerossDeviceAnalyzer:
    def __init__(self, json_file):
        self.json_file = json_file
        self.device_names = []
        self.onoff_history = []
        self.time_history = []
        self.time = time.time()

    def analyze_packets(self):
        with open(self.json_file, 'r') as file:
            data = json.load(file)

        for packet in data:
            try:
                payload = packet['payload']
                # Check if payload is a dictionary
                if isinstance(payload, dict):
                    dev_name = payload.get('devName')
                    if dev_name and dev_name not in self.device_names:
                        self.device_names.append(dev_name)
                # Check if payload is a string
                elif isinstance(payload, str):
                    #print("Payload as string:", payload)
                    onoff_index = payload.find("onoff")
                    if onoff_index != -1:
                        # Look for the next integer after "onoff"
                        next_char_index = onoff_index + len("onoff")
                        while next_char_index < len(payload) and not payload[next_char_index].isdigit():
                            next_char_index += 1
                        if next_char_index < len(payload):
                            next_integer = ""
                            while next_char_index < len(payload) and payload[next_char_index].isdigit():
                                next_integer += payload[next_char_index]
                                next_char_index += 1
                            print("Next integer after 'onoff':", next_integer)
                            self.onoff_history.append(int(next_integer))
                            self.time_history.append(time.time() - self.time)
                            self.plot_live_graph(self.time_history, self.onoff_history)

                    print('------')
            except KeyError:
                print("Error: field not found in the payload.")

    def print_unique_device_names(self):
        print("Unique Device Names:")
        for dev_name in self.device_names:
            print(dev_name)

    # Fonction pour afficher le graphique en temps réel
    def plot_live_graph(self, x_data, y_data):
        plt.clf()  # Effacer le graphique précédent
        plt.step(x_data, y_data)  # Tracer le nouveau graphique
        plt.xlabel('Temps')
        plt.ylabel('On/Off')
        plt.title('Graphique en temps réel')
        plt.grid(True)
        plt.pause(0.01)  # Pause pour actualiser le graphique


