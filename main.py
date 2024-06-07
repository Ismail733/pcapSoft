from scapy.all import sniff, Ether, IP, TCP, Raw, wrpcap, DNS
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
        # Capture les packets sur l'interface wlp6s0
        self.captured_packets = sniff(iface="wlp6s0", prn=self.process_packet)

    # Fonction pour traiter et afficher les paquets capturés
    def process_packet(self, packet):
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
        elif packet.haslayer(Ether) and packet.haslayer(IP) and packet.haslayer(TCP):
            # Vérifier si les adresses MAC source et destination correspondent à celles spécifiées
            ethernet_info = {
                "src_mac": packet[Ether].src,
                "dst_mac": packet[Ether].dst
            }

            ip_info = {
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst
            }
            tcp_info = {
                "src_port": packet[TCP].sport,
                "dst_port": packet[TCP].dport
            }
            payload = bytes(packet[TCP].payload)
            if b"HTTP/1.1" in payload or b"GET" in payload or b"POST" in payload:
                try:
                    decoded_payload = payload.decode('utf-8')
                    # Pour la prise Meross, il y a deux type de packet, les dictionnaires avec le nom du device, et les string avec la valeur onoff de la prise
                    # Regarde si le payload est un dictionnaire
                    if isinstance(decoded_payload, dict):
                        dev_name = decoded_payload.get('devName')
                        if dev_name and dev_name not in self.device_names:
                            self.device_names.append(dev_name)
                    
                    # Regarde si le payload est un string
                    elif isinstance(decoded_payload, str):
                        onoff_index = decoded_payload.find("onoff")
                        if onoff_index != -1:
                            # Trouver le prochain entier après "onoff"
                            next_char_index = onoff_index + len("onoff")
                            while next_char_index < len(decoded_payload) and not decoded_payload[next_char_index].isdigit():
                                next_char_index += 1
                            if next_char_index < len(decoded_payload):
                                next_integer = ""
                                while next_char_index < len(decoded_payload) and decoded_payload[next_char_index].isdigit():
                                    next_integer += decoded_payload[next_char_index]
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
                    else:
                        print(payload)
                except UnicodeDecodeError:
                    print("Error: cannot decode the payload.")               
                    
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

    def plot_live_graph(self, x_data, y_data):
        plt.clf()  # Effacer le graphique précédent
        plt.step(x_data, y_data)  # Tracer le nouveau graphique
        plt.xlabel('Temps')
        plt.ylabel('On/Off')
        plt.title('Graphique en temps réel')
        plt.grid(True)
        plt.pause(0.001)

# Créer une instance de la classe Capture
capture = Capture()

#Lance la capture dans le main thread pour éviter les erreurs matplotlib
capture.capture_traffic()

plt.show()