FROM boky/postfix:latest

# Creiamo il file alias (fondamentale mappare root e victim)
RUN echo "postmaster: root" > /etc/aliases && \
    echo "victim: root" >> /etc/aliases

# Generiamo il database LMDB. 
# Forziamo Postfix a guardare ESATTAMENTE questo file bypassando auto-configurazioni errate.
RUN postalias lmdb:/etc/aliases && \
    newaliases && \
    postconf -e "alias_maps = lmdb:/etc/aliases" && \
    postconf -e "alias_database = lmdb:/etc/aliases" && \
    postconf -e "local_recipient_maps = proxy:unix:passwd.byname \$alias_maps"

# Creazione dell'utente di sistema per la ricezione locale
RUN useradd -m -s /bin/bash victim

# Permessi: il demone postfix deve poter leggere il DB
RUN chown root:root /etc/aliases* && chmod 644 /etc/aliases*