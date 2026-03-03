import csv
import os

class JA3Classifier:
    def __init__(self, blacklist_path="/home/mitmproxy/data/ja3_blacklist.csv"):
        self.malware_db = {}

        # Definiamo alcuni hash noti per script Python standard
        self.scripting_db = {
            "3b5074b1b590322741a469f345388c5f": "Python smtplib / requests",
            "ed71105d21b0c098f56b4599f7fb1d74": "Python smtplib (Docker Attacker)",
            "9735870094136e053158434604d55b0b": "Go-http-client"
        }
        self._load_malware_db(blacklist_path)

    # Carica il database di malware da un file CSV, ignorando le righe commentate (che iniziano con #)
    def _load_malware_db(self, path):
        if os.path.exists(path):
            with open(path, mode='r', encoding='utf-8') as f:
                reader = csv.reader(filter(lambda row: row[0] != '#', f))
                for row in reader:
                    if len(row) >= 2:
                        self.malware_db[row[0]] = row[1]

    # Classificazione basata su hash JA3
    def classify(self, ja3_hash):

        if ja3_hash in self.malware_db:
            return "MALWARE", self.malware_db[ja3_hash] # Se l'hash è presente nel database, ritorna MALWARE e il nome della minaccia
        if ja3_hash in self.scripting_db:
            return "AUTOMATION", self.scripting_db[ja3_hash] # Se l'hash è presente nel database di scripting, ritorna AUTOMATION e il nome dello script
        return "UNKNOWN", "Client non identificato"