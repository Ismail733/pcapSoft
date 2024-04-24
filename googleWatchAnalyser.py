import json

class GoogleWatchAnalyzer:
    def __init__(self, json_file):
        self.json_file = json_file
        self.analyzed_packets = []

    def analyze(self):
        with open(self.json_file, 'r') as f:
            packet_list = json.load(f)

        for packet in packet_list:
            if packet["raw_data"] is not None and "connectivitycheck.gstatic.com" in packet["raw_data"]:
                packet["google_watch_status"] = "Google Watch device is connected"


            self.analyzed_packets.append(packet)

    def to_json(self, output_file="pcap_data.json"):
        json_data = json.dumps(self.analyzed_packets, indent=4)
        print(json_data)

        with open(output_file, "w") as json_file:
            json_file.write(json_data)

# Example usage:
if __name__ == "__main__":
    analyzer = GoogleWatchAnalyzer("pcap_data.json")
    analyzer.analyze()
    analyzer.to_json()
