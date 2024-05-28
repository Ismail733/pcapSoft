from scapy.all import *
import threading
import keyboard

import threading
from scapy.all import sniff, wrpcap

# Fonction pour capturer le trafic en arrière-plan
class Capture:
    def __init__(self):
        self.captured_packets = None


    def capture_traffic(self):
        print("Capture de trafic en cours. Appuyez sur 'q' pour arrêter.")
        self.captured_packets = sniff(prn=self.process_packet)

    # Fonction pour traiter et afficher les paquets capturés
    def process_packet(self, packet):
        print(packet.summary())
        # Vous pouvez ajouter d'autres traitements ici si nécessaire
        self.analyze_packets()
        wrpcap("captured_packets.pcapng", packet, append=True)
        

    def analyze_packets(self,packet):
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

# Créer une instance de la classe Capture
capture = Capture()

# Lancer la capture de trafic dans un thread
capture_thread = threading.Thread(target=capture.capture_traffic)
capture_thread.daemon = True
capture_thread.start()

# Fonction pour arrêter la capture de trafic lorsque la touche "q" est pressée
def stop_capture(e):
    if e.name == 'q':
        print("Arrêt de la capture de trafic...")
        capture_thread.join()
        
# Associer la fonction stop_capture à la pression de la touche "q"
keyboard.on_press(stop_capture)

# Attendre indéfiniment jusqu'à ce que la touche "q" soit pressée
keyboard.wait('q')

sys.exit()




def analyze_packets(self, packet):
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