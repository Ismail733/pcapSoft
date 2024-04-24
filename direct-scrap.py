from scapy.all import *
import threading
import keyboard

# Fonction pour capturer le trafic en arrière-plan
def capture_traffic():
    global captured_packets
    captured_packets = sniff(prn=process_packet)

# Fonction pour traiter et afficher les paquets capturés
def process_packet(packet):
    print(packet.summary())
    wrpcap("captured_packets.pcapng", packet, append=True)
    # Vous pouvez ajouter d'autres traitements ici si nécessaire

# Lancer la capture de trafic dans un thread
capture_thread = threading.Thread(target=capture_traffic)
capture_thread.daemon = True
capture_thread.start()

print("Capture de trafic en cours. Appuyez sur 'q' pour arrêter.")

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
sys.exit()