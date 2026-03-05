import hashlib
import requests
from mitmproxy import tls, tcp
from intelligence import JA3Classifier
import shared_state

# Istanza globale del classificatore
classifier = JA3Classifier()

# Rileva valori GREASE (RFC 8701). Supporta sia interi che altri tipi, filtrando solo gli interi validi.
def is_grease(val: int) -> bool:
    if not isinstance(val, int):
        return False
    return (val & 0x0f0f) == 0x0a0a

# Estrae i 5 parametri JA3 in modo rigoroso: Version, Ciphers, Extensions, EllipticCurves, EllipticCurveFormats
def get_ja3_fingerprint(ch: tls.ClientHelloData.client_hello) -> str: # ch sarà un oggetto ClientHelloData.client_hello, che contiene tutte le informazioni necessarie per estrarre i parametri JA3
    # TLS Version (Valore numerico del record ClientHello)
    # ch.client_version è un bytes di 2 elementi (es. b'\x03\x03')
    try:
        tls_version = str(ch.version)
    except AttributeError:
        # Fallback nel caso in cui la proprietà abbia un nome diverso
        tls_version = str(int.from_bytes(getattr(ch, "client_version", b'\x03\x03'), "big"))

    # Cipher Suites (Escludendo GREASE)
    ciphers = "-".join(str(c) for c in ch.cipher_suites if not is_grease(c))

    # Extensions
    # Nelle nuove API, le chiavi del dizionario extensions sono gli ID numerici
    # Dobbiamo estrarre solo gli ID, filtrando i GREASE
    try:
        raw_exts = ch.extensions.keys() if hasattr(ch.extensions, "keys") else ch.extensions
        ext_ids = [str(e) for e in raw_exts if isinstance(e, int) and not is_grease(e)]
    except Exception:
        ext_ids = []
    extensions = "-".join(ext_ids)

    # Supported Groups (Parsing manuale dai byte dell'estensione 10)
    supported_groups = ""
    if 10 in ch.extensions:
        raw_groups = ch.extensions[10] # Questi sono i bytes dell'estensione
        groups = []
        try:
            # Il formato è: 2 byte lunghezza totale + N gruppi (2 byte ciascuno)
            # Partiamo dall'indice 2 per saltare la lunghezza
            for i in range(2, len(raw_groups), 2):
                if i + 2 <= len(raw_groups):
                    g = int.from_bytes(raw_groups[i:i+2], "big")
                    if not is_grease(g):
                        groups.append(str(g))
            supported_groups = "-".join(groups)
        except Exception:
            supported_groups = ""

    # EC Point Formats (Parsing manuale dai byte dell'estensione 11)
    ec_formats = ""
    if 11 in ch.extensions:
        raw_formats = ch.extensions[11] # Questi sono i bytes dell'estensione
        try:
            # Il formato è: 1 byte lunghezza lista + N formati (1 byte ciascuno)
            # Partiamo dall'indice 1 per saltare la lunghezza
            formats = [str(raw_formats[i]) for i in range(1, len(raw_formats))]
            ec_formats = "-".join(formats)
        except Exception:
            ec_formats = ""

    # Costruzione stringa JA3 finale
    ja3_string = f"{tls_version},{ciphers},{extensions},{supported_groups},{ec_formats}"
    return ja3_string

# Handler per ClientHello, attivato ad ogni handshake TLS
def tls_clienthello(data: tls.ClientHelloData):
    # Estrazione metadati identificativi dal contesto del flusso
    client_ip = data.context.client.peername[0]
    client_id = data.context.client.id
    ch = data.client_hello

    # Generazione della stringa JA3 basata sui parametri TLS (Version, Ciphers, Extensions, Elliptic Curves)
    ja3_string = get_ja3_fingerprint(ch)
    ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()

    # Interrogazione del database locale (malware_db e scripting_db)
    category, detail = classifier.classify(ja3_hash)
    
    # Memorizzazione dello stato nella memoria condivisa per l'analisi successiva del Proxy (Nodo 2)
    shared_state.ja3_memory[client_id] = {
        "category": category,
        "detail": detail,
        "hash": ja3_hash
    }
    
    # Gestione delle due categorie principali: MALWARE vs AUTOMATION/UNKNOWN
    if category == "MALWARE":
        print(f"[JA3-BLOCK] Identificato {detail}. Interruzione immediata di Client e Server.")
        
        # Chiudiamo la connessione verso il Mail Server (se già aperta)
        # Questo evita che Postfix rimanga in stato 'connect' nel log senza ricevere nulla
        data.context.server.error = "Security Policy Block" 
        data.context.client.error = "Security Policy Block"

        # Killiamo il flow principale come sicurezza definitiva
        if hasattr(data.context, "flow"):
            data.context.flow.kill()
            
    else:
        # Se non è malware, il flusso procede verso l'estrazione del payload SMTP
        print(f"[JA3-FINGERPRINT] Classificato come {category}. [JA3:{ja3_hash}] Inoltro al payload extractor.")