import matplotlib.pyplot as plt
import numpy as np
import time

# Fonction pour afficher le graphique en temps réel
def plot_live_graph(x_data, y_data):
    plt.clf()  # Effacer le graphique précédent
    plt.plot(x_data, y_data)  # Tracer le nouveau graphique
    plt.xlabel('Temps')
    plt.ylabel('On/Off')
    plt.title('Graphique en temps réel')
    plt.grid(True)
    plt.pause(0.01)  # Pause pour actualiser le graphique

# Boucle principale pour surveiller les changements de la valeur d'entrée
x_data = []
y_data = []
while True:
    # Remplacer cette partie avec la fonction qui récupère la valeur d'entrée
    new_value = np.random.rand()  # Exemple de génération de valeur aléatoire
    x_data.append(len(x_data))  # Ajouter une nouvelle valeur pour l'axe x
    y_data.append(new_value)  # Ajouter une nouvelle valeur pour l'axe y
    plot_live_graph(x_data, y_data)  # Afficher le graphique en temps réel avec les nouvelles données
    time.sleep(1)  # Attendre avant de mettre à jour à nouveau le graphique
