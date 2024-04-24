import json
import re
import datetime

class MerossDeviceAnalyzer:
    def __init__(self, json_file):
        self.json_file = json_file
        self.device_names = []

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
                    timestamp = payload.find("timestamp")
                    onoff_index = payload.find("onoff")
                    if onoff_index != -1:
                        unixTimestamp=int(re.search(r'"timestamp":(\d+)',str(payload)).group(1))
                        print(datetime.datetime.fromtimestamp(unixTimestamp).strftime('%Y-%m-%d %H:%M:%S'))
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
                    print('------')
            except KeyError:
                print("Error: field not found in the payload.")

    def print_unique_device_names(self):
        print("Unique Device Names:")
        for dev_name in self.device_names:
            print(dev_name)

# Usage
analyzer = MerossDeviceAnalyzer("packet_info.json")
analyzer.analyze_packets()
analyzer.print_unique_device_names()
