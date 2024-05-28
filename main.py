from scapy.all import *
import json
import matplotlib.pyplot as plt
import time
from threading import Thread

class MerossAnalyzer:
    def __init__(self, file_path, source_address, destination_address):
        self.file_path = file_path
        self.source_address = source_address
        self.destination_address = destination_address
        self.packet_info_list = []
        self.onoff_values = []  # List to store on/off values over time

    def analyze_packets(self):
        with PcapReader(self.file_path) as pcap_reader:
            for packet in pcap_reader:
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst

                if (src_mac == self.source_address or src_mac == self.destination_address) and (dst_mac == self.source_address or dst_mac == self.destination_address):
                    if Raw in packet and packet[Raw].load:
                        payload = packet[Raw].load.decode('utf-8')
                        onoff_index = payload.find("onoff")
                        if onoff_index != -1:
                            next_char_index = onoff_index + len("onoff")
                            while next_char_index < len(payload) and not payload[next_char_index].isdigit():
                                next_char_index += 1
                            if next_char_index < len(payload):
                                next_integer = ""
                                while next_char_index < len(payload) and payload[next_char_index].isdigit():
                                    next_integer += payload[next_char_index]
                                    next_char_index += 1
                                self.onoff_values.append(int(next_integer))
                                print(f"Next integer after 'onoff': {next_integer}")

# Function to plot live graph
def plot_live_graph(x_data, y_data):
    plt.clf()  # Clear the previous plot
    plt.plot(x_data, y_data, marker='o')  # Plot new graph with markers
    plt.xlabel('Time')
    plt.ylabel('On/Off')
    plt.title('Real-time On/Off Graph')
    plt.grid(True)
    plt.pause(0.01)  # Pause to update the graph

# Function to update the graph in a separate thread
def update_graph(analyzer):
    x_data = []
    while True:
        if analyzer.onoff_values:
            y_data = analyzer.onoff_values
            x_data = list(range(len(y_data)))  # Generate x values
            plot_live_graph(x_data, y_data)  # Update the graph with new data
        time.sleep(1)  # Sleep before updating again

# Usage
file_path = '2_meross_on_off.pcapng'
source_address = 'aa:f9:24:38:27:e1'
destination_address = '48:e1:e9:3a:3a:b7'

analyzer = MerossAnalyzer(file_path, source_address, destination_address)

# Start a thread to update the graph in real-time
graph_thread = Thread(target=update_graph, args=(analyzer,))
graph_thread.daemon = True  # Daemonize thread to exit when main program exits
graph_thread.start()

# Start analyzing packets
analyzer.analyze_packets()
