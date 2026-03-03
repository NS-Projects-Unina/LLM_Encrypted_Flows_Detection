# LLM Encrypted Flows Detection

## Panoramica del Sistema

Il sistema è un IPS/IDS operante a Livello 7 (Applicativo) progettato per la Deep Packet Inspection su traffico e-mail crittografato (SMTPS). Il sistema intercetta il traffico, ne estrae il payload MIME e utilizza un'architettura di intelligenza artificiale ibrida per classificare le minacce. L'obiettivo primario è distinguere tra comunicazioni legittime, attacchi di phishing scritti da operatori umani e frodi generate automaticamente tramite Large Language Models (LLM).

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
* Minimo 8 GB di RAM allocati al demone Docker per consentire il caricamento in memoria dei tensori (RoBERTa + GPT-2).

## Installazione e Avvio

Avviare un terminale nella directory radice del progetto ed eseguire i seguenti comandi:

```bash
docker-compose build
docker-compose up -d
docker logs -f inference-engine

```

**Dettaglio delle istruzioni di avvio:**

* `docker-compose build`: Esegue la compilazione delle immagini Docker e l'installazione delle dipendenze di sistema e di rete.
* `docker-compose up -d`: Avvia l'infrastruttura in background (modalità detached), istanziando le reti virtuali e i container isolati.
* `docker logs -f inference-engine`: Aggancia lo standard output del nodo IA per monitorare il corretto caricamento dei pesi LoRA e l'inizializzazione del servizio.

## Esecuzione di un Test di Validazione

A infrastruttura avviata, è possibile simulare un attacco e monitorarne la mitigazione.

**Fase 1: Lancio dell'attacco**

```bash
docker exec -it attacker bash
python3 attack_sim.py

```

**Dettaglio tecnico:** Il primo comando apre una sessione terminale interattiva all'interno del nodo attaccante. Il secondo esegue lo script di simulazione che invia il payload SMTPS.

**Fase 2: Analisi e ispezione**

```bash
docker logs -f edge-proxy

```

**Dettaglio tecnico:** Mostra in tempo reale l'output del gateway, evidenziando l'intercettazione TLS, l'estrazione a Livello 7 e la risposta di classificazione ottenuta dal nodo IA.

**Fase 3: Verifica della coda di destinazione**

```bash
docker exec -it mail-server postqueue -p

```

