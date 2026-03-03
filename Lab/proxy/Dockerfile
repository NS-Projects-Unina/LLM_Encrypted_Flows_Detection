# Partiamo dall'immagine ufficiale di mitmproxy
FROM mitmproxy/mitmproxy:latest

# Installazione dipendenze di sistema

# tcpdump e libpcap sono necessari a Scapy per sniffare i pacchetti RAW
# curl serve per scaricare la blacklist di Abuse.ch
RUN apt-get update && apt-get install -y \
    tcpdump \
    libpcap-dev \
    python3-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Installazione librerie Python necessarie

# scapy: per l'analisi dei pacchetti TLS (Extensions, Groups, Formats)
# requests: per inviare gli alert al Nodo Analisi (10.0.1.20)
RUN pip install scapy requests

# Download della Blacklist JA3 (Abuse.ch)

# Scarichiamo il database IoC direttamente nel container in fase di build
RUN mkdir -p /home/mitmproxy/data && \
    curl -o /home/mitmproxy/data/ja3_blacklist.csv https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv


# Copia degli script di automazione (telemetria e payload)

# Assicurati che la cartella ./scripts esista sul tuo host
COPY . /home/mitmproxy/scripts

RUN chmod -R 755 /home/mitmproxy/scripts
# Impostiamo la directory di lavoro
WORKDIR /home/mitmproxy/scripts

# Il comando di avvio viene solitamente gestito nel docker-compose.yml
# ma specifichiamo il punto di ingresso per mitmproxy
# Rimuovi l'ENTRYPOINT precedente e sostituiscilo con questo
ENTRYPOINT ["mitmdump", "-p", "465", "--mode", "reverse:tcp://10.0.1.10:25", "-s", "/home/mitmproxy/scripts/payload_extraction.py", "-s", "/home/mitmproxy/scripts/fingerprinting.py"]