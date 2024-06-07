****************************************Introduction********************************************

Ces codes ont pour but de reconnaître les appareils IOT sur un reseaux et de mettre en évidence l'activité de ces appareils. Le code est crée au cas par cas, voici les trois appareil traité une prise MEROSS MSS310, un google home et une montre google watch pixel.


****************************************Les fichiers********************************************

- main1.py #Le fichier autonome à lancer avec les droits administrateur (sudo sous linux) qui capture les packets et les analyses et affiche les résultats pour la prise.


- direct-scrap.py #Ce fichier fait la capture des packets les affiches et enregistre dans le fichier captured_packets.pcapng . Peut-être arreté en appuyant sur 'q'.

- MerossReader.py #Prend un fichier pcapng en entrée et sort un fichier json avec les paquets meross. Utilise les adresses MAC pour filtrer les messages contrairement a main.py qui vérifie que c'est une requête HTTP.

- MerossAnalyser.py #Récupére le fichier json généré par MerossReader, analyse l'état de la prise et les affiches dans un graphique.


****************************************Utilisation*********************************************

Pour tout faire fonctionner main.py un ordinateur doit être utilisé comme "box" wifi et partager la connexion aux autres appareils. Nous avons utilisé des ordinateurs sous Linux qui disposaient de cette fonction Hotspot. Pour que l'ordinateur ait lui-même une connexion internet nous avons fait un partage de données avec un téléphone connecté en USB (paramètre : modem usb). Vous devez télécharger l'application Meross sur un autre téléphone connecté au partage wifi pour utiliser la prise et la configurer pour qu'elle se connecte au partage (Vous devez être en réseau local pour voir les packets http de la prise, pour cela vous pouvez déconnecter l'ordinateur du réseau internet). Vous pouvez ensuite lancer main.py et activer/désactiver la prise et voir comment c'est stylé.

Pour utiliser le merossReader.py vous pouvez utiliser le fichier crée par direct-scrap.py ou enregistrer par wireshark, veillez a bien préciser les bonnes adresses MAC pour le filtrage des paquets.