from pprint import pprint
from scapy.all import *
import json

logfile = rdpcap('PCAPdroid_06_mars_14_53_23.pcap')

# Convert each packet to a dictionary
packet_list = []
for packet in logfile:
    ip_layer = packet.getlayer(IP)
    packet_dict = {
        "timestamp": str(packet.time),
        "source_mac": packet.src,
        "destination_mac": packet.dst,
        "source_ip": ip_layer.src if ip_layer else None,
        "destination_ip": ip_layer.dst if ip_layer else None,
        "raw1": packet.summary(),
        "raw2": packet.show2(),
        # Add more fields as needed
    }
    packet_list.append(packet_dict)

# Convert the list of dictionaries to JSON
json_data = json.dumps(packet_list, indent=4)

# Output JSON data
#pprint(list(logfile))

# Optionally, write JSON data to a file
with open("pcap_data.json", "w") as json_file:
    json_file.write(json_data)

