from scapy.all import sniff, Raw
import threading
import matplotlib.pyplot as plt
import time
import sys

class RealTimeAnalyzer:
    def __init__(self):
        self.device_names = []
        self.onoff_history = []
        self.time_history = []
        self.start_time = time.time()
        plt.ion()  # Activer le mode interactif

    def process_packet(self, packet):
        print(packet.summary())  # Print the summary of the packet
        if Raw in packet and packet[Raw].load:
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')  # Ignore les erreurs de décodage
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
                        print("Next integer after 'onoff':", next_integer)
                        self.onoff_history.append(int(next_integer))
                        self.time_history.append(time.time() - self.start_time)
                        self.plot_live_graph(self.time_history, self.onoff_history)
            except Exception as e:
                print(f"Error processing packet: {e}")

    # Fonction pour afficher le graphique en temps réel
    def plot_live_graph(self, x_data, y_data):
        plt.clf()  # Effacer le graphique précédent
        plt.step(x_data, y_data)  # Tracer le nouveau graphique
        plt.xlabel('Temps')
        plt.ylabel('On/Off')
        plt.title('Graphique en temps réel')
        plt.grid(True)
        plt.pause(0.01)  # Pause pour actualiser le graphique

# Fonction pour capturer le trafic en arrière-plan
def capture_traffic(analyzer):
    sniff(prn=analyzer.process_packet)

# Initialiser l'analyseur en temps réel
analyzer = RealTimeAnalyzer()

# Lancer la capture de trafic dans un thread
capture_thread = threading.Thread(target=capture_traffic, args=(analyzer,))
capture_thread.daemon = True
capture_thread.start()

print("Capture de trafic en cours. Appuyez sur 'Entrée' pour arrêter.")

# Utiliser input() pour arrêter la capture
input('Appuyez sur Entrée pour arrêter...\n')

print("Arrêt de la capture de trafic...")
plt.close()
sys.exit()
