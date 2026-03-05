# LLM Encrypted Flows Detection

## Panoramica del Sistema
NetSentinel è un sistema IPS/IDS operante a Livello 7 (Applicativo) progettato per la Deep Packet Inspection su traffico e-mail crittografato (SMTPS). Il sistema intercetta il traffico, ne estrae il payload MIME e utilizza un'architettura di intelligenza artificiale ibrida per classificare le minacce. L'obiettivo primario è distinguere tra comunicazioni legittime, attacchi di phishing scritti da operatori umani e frodi generate automaticamente tramite Large Language Models (LLM).

## Architettura di Rete e Specifiche Tecniche
L'infrastruttura è containerizzata e segmentata in due reti virtuali isolate (`public-net`: 10.0.0.0/24 e `private-net`: 10.0.1.0/24) per garantire la sicurezza del backend.

* **Attacker Node (Simulazione):** Container posizionato sulla rete pubblica. Esegue script Python per generare traffico SMTPS malevolo verso il proxy, simulando vettori di attacco MIME/Base64.
* **Edge-Proxy (Security Gateway - 10.0.0.5 / 10.0.1.5):** Nodo dual-homed basato su `mitmproxy`. Intercetta le connessioni TLS sulla porta 465 (public-net), estrae i payload a Livello 7 ed esegue il fingerprinting JA3. Inoltra i dati al nodo IA per la validazione. Se legittimo, il traffico viene reinstradato sulla porta 25 verso il server di posta interno.
* **Inference Engine (AI Node - 10.0.1.20):** Microservizio REST isolato (FastAPI su HTTPS/5000). Implementa una logica di "Override Statistico" basata su:
  * *Classificazione Semantica:* Modello `roberta-base` fine-tuned con adattatori LoRA su un dataset quadri-classe (Human/AI x Legit/Phishing). Quantizzato a 8-bit per l'ottimizzazione dell'inferenza.
  * *Analisi Statistica:* Modello `GPT-2` per il calcolo della Perplexity testuale, essenziale per mitigare i bias semantici verso il linguaggio formale degli LLM.
* **Mail Server (10.0.1.10):** Istanza Postfix configurata in modo restrittivo. Accetta comunicazioni unicamente dalla `private-net`, risultando inaccessibile dall'esterno.

## Prerequisiti
* Sistema operativo host basato su UNIX (Linux/macOS) compatibile con architettura ARM64/AMD64.
* Docker Engine (v20.10+) e Docker Compose (v2.0+).
* Minimo 8 GB di RAM allocati al demone Docker per il caricamento in memoria dei tensori (RoBERTa + GPT-2).

## Installazione e Avvio
Avviare un terminale nella directory radice del progetto:

```bash
# Compilazione delle immagini e installazione delle dipendenze
docker-compose build

# Avvio dell'infrastruttura in modalità detached
docker-compose up -d

# Monitoraggio dell'inizializzazione del nodo IA (caricamento pesi LoRA)
docker logs -f inference-engine

## Esecuzione di un Test di Validazione

docker exec -it attacker-node bash
python3 attack_sim.py
docker logs -f edge-proxy
docker logs -f mail-server
docker exec -it mail-server cat /var/mail/root