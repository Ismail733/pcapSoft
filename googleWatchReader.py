from pprint import pprint
from scapy.all import *
import json

class GoogleWatchReader:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packet_list = []

    def parse_packets(self):
        logfile = rdpcap(self.pcap_file)
        for packet in logfile:
            ip_layer = packet.getlayer(IP)
            packet_dict = {
                "timestamp": str(packet.time),
                "source_mac": packet.src,
                "destination_mac": packet.dst,
                "source_ip": ip_layer.src if ip_layer else None,
                "destination_ip": ip_layer.dst if ip_layer else None,
                "summary": packet.summary(),
                "raw_data": packet.show(dump=True),
            }

            # Handle payload decoding
            if Raw in packet and packet[Raw].load:
                try:
                    payload = json.loads(packet[Raw].load.decode('utf-8'))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    # If decoding fails, store raw payload
                    payload = packet[Raw].load.hex()  # Convert to hex representation
            else:
                payload = None

            # Add payload to packet dictionary
            packet_dict["payload"] = payload

            # Append packet dictionary to packet_list
            self.packet_list.append(packet_dict)

    def to_json(self, output_file="pcap_data.json"):
        # Convert the list of dictionaries to JSON
        json_data = json.dumps(self.packet_list, indent=4)
        
        # Optionally, write JSON data to a file
        with open(output_file, "w") as json_file:
            json_file.write(json_data)

# Example usage:
if __name__ == "__main__":
    reader = GoogleWatchReader('PCAPdroid_06_mars_14_53_23.pcap')
    reader.parse_packets()
    reader.to_json()
