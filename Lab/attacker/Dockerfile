FROM python:3.10-slim

# Installazione dipendenze
RUN apt-get update && apt-get install -y \
    ca-certificates \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Creiamo la directory e impostiamo i permessi corretti
RUN mkdir -p /usr/local/share/ca-certificates/extra
WORKDIR /scripts

# Non eseguiamo update-ca-certificates qui perché i volumi non sono ancora montati