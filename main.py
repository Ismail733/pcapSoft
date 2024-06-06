from scapy.all import sniff, Ether, IP, TCP, Raw, wrpcap, DNS
import threading
import keyboard
import threading
import json
import matplotlib.pyplot as plt
import time

# Classe qui capture les packets et les analyses puis display les résultats
class Capture:
    def __init__(self):
        self.captured_packets = None
        self.onoff_history = []
        self.time_history = []
        self.time = time.time()
        self.device_names = []


    def capture_traffic(self):
        print("Capture de trafic en cours. Appuyez sur 'q' pour arrêter.")
        self.captured_packets = sniff(prn=self.process_packet)

    # Fonction pour traiter et afficher les paquets capturés
    def process_packet(self, packet):
        #print(packet)
        # Vous pouvez ajouter d'autres traitements ici si nécessaire
        self.analyze_packets(packet)
        wrpcap("captured_packets.pcapng", packet, append=True)
        
    # Fonction pour analyser les paquets capturés.
    def analyze_packets(self,packet):
        # Regarder si le packet est une requête DNS et regarde le site accedé
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:  # DNS request
            dns_layer = packet.getlayer(DNS)
            print(f"DNS Request for {dns_layer.qd.qname.decode('utf-8')}")
        # Vérifier si le paquet a une couche Ethernet et IP
        elif packet.haslayer(Ether) and packet.haslayer(IP):
        
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst

            # Vérifier si les adresses MAC source et destination correspondent à celles spécifiées
        
            ethernet_info = {
                "src_mac": src_mac,
                "dst_mac": dst_mac
            }

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

                # Pour la prise Meross, il y a deux type de packet, les dictionnaires avec le nom du device, et les string avec la valeur onoff de la prise
                # Check if payload is a dictionary
                if isinstance(payload, dict):
                    dev_name = payload.get('devName')
                    if dev_name and dev_name not in self.device_names:
                        self.device_names.append([dev_name,src_mac])
                # Check if payload is a string
                elif isinstance(payload, str):
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
                            packet_info = {
                            "ethernet": ethernet_info,
                            "ip": ip_info,
                            "tcp": tcp_info,
                            "payload": next_integer,
                            "timestamp": str(packet.time),
                            }
                            print(packet_info)
                            self.onoff_history.append(int(next_integer))
                            self.time_history.append(time.time() - self.time)
                            self.plot_live_graph(self.time_history, self.onoff_history)
                
                # Pour les packets google, on regarde si le payload contient connectivitycheck.gstatic.com
                raw_data=packet.show(dump=True)
                if raw_data is not None and "connectivitycheck.gstatic.com" in raw_data :
                    packet_info = {
                    "ethernet": ethernet_info,
                    "ip": ip_info,
                    "tcp": tcp_info,
                    "payload": raw_data,
                    "timestamp": str(packet.time),
                    "raw_data" : raw_data
                    }
                    print(packet_info)
                        


    def plot_live_graph(self, x_data, y_data):
        plt.clf()  # Effacer le graphique précédent
        plt.step(x_data, y_data)  # Tracer le nouveau graphique
        plt.xlabel('Temps')
        plt.ylabel('On/Off')
        plt.title('Graphique en temps réel')
        plt.grid(True)
        # Pause pour actualiser le graphique

source_address = 'aa:f9:24:38:27:e1'
destination_address = '48:e1:e9:3a:3a:b7'

# Créer une instance de la classe Capture
capture = Capture(source_address, destination_address)

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

# Enregistrer les paquets capturés dans un fichier PCAPNG
print("Trafic capturé enregistré dans captured_packets.pcapng.")
print("nombre d'appareil : ",len(capture.device_names))

plt.show()