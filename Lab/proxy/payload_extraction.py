from mitmproxy import tcp
import email # Per analizzare strutture multipart, estrarre i boundary e risolvere dinamicamente le codifiche di trasferimento (come Base64 e Quoted-Printable).
from email.policy import default
import requests
import shared_state

# Configurazione nodo di inferenza
INFERENCE_URL = "https://10.0.1.20:5000/analyze"
# Percorso del certificato TLS per la comunicazione sicura con il nodo di inferenza
CERT_PATH = "/certs/cert.pem"

session_state = {}

# Funzione per estrarre il testo in chiaro da un payload SMTP, supporta sia messaggi semplici che multipart, e gestisce dinamicamente le codifiche di trasferimento
def extract_clear_text(raw_bytes: bytes) -> str:
    msg = email.message_from_bytes(raw_bytes, policy=default)
    extracted_text = ""
    
    # Se il messaggio è multipart, iteriamo su tutte le parti per estrarre il testo, altrimenti estraiamo direttamente il payload. Gestiamo anche le codifiche di trasferimento in modo dinamico, lasciando che la libreria email si occupi di decodificare correttamente i contenuti.
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            
            if content_type == "text/plain" and "attachment" not in content_disposition:
                try:
                    extracted_text += part.get_content()
                except Exception:
                    continue
    else:
        if msg.get_content_type() == "text/plain":
            try:
                extracted_text = msg.get_content()
            except Exception:
                pass
                
    return extracted_text.strip()


def tcp_message(flow: tcp.TCPFlow): # Handler per i messaggi TCP, attivo su ogni pacchetto del flusso TCP, ci permette di analizzare i dati in transito e applicare logiche IPS basate sui metadati JA3
    message = flow.messages[-1]
    client_id = flow.client_conn.id
    
    # Inizializziamo lo stato della sessione per questo client se non esiste già, questo ci permette di tracciare se siamo nella sezione DATA di una mail e di accumulare il payload
    if client_id not in session_state:
        session_state[client_id] = {"in_data": False, "buffer": b"", "intercepted_messages": [], "ja3_category": "UNKNOWN"}

    # Analizziamo solo i messaggi provenienti dal client verso il server, ignorando quelli di risposta del server, questo perché vogliamo applicare le logiche IPS sui dati in ingresso
    if message.from_client:
        content_raw = message.content
        state = session_state[client_id]

        # Rilevamento comando DATA
        if b"DATA" == content_raw.upper().strip():
            
            # LETTURA DALLA MEMORIA CONDIVISA PYTHON USANDO L'ID DEL CLIENT
            ja3_info = shared_state.ja3_memory.get(client_id, {})
            ja3_cat = ja3_info.get("category", "UNKNOWN")
            ja3_detail = ja3_info.get("detail", "Unknown")
            ja3_hash = ja3_info.get("hash", "")

            state["ja3_category"] = ja3_cat
            state["ja3_detail"] = ja3_detail
            state["ja3_hash"] = ja3_hash
            
            # Se il JA3 è già classificato come MALWARE, killiamo subito
            if ja3_cat == "MALWARE":
                flow.kill()
                return
            
            # Attiviamo la cattura del payload nella sezione DATA
            state["in_data"] = True
            print(f"[IPS] Comando DATA rilevato. Inizio cattura payload (JA3: {ja3_cat})")
            return

        if state["in_data"]:

            # Intercettazione e Accumulo
            flow.intercept() # Intercettiamo il flusso per analizzare il payload prima di lasciarlo passare
            state["buffer"] += content_raw
            state["intercepted_messages"].append(message)

            # Analisi alla chiusura della mail
            if content_raw.strip() == b"." or content_raw.endswith(b"\r\n.\r\n"): # Il punto singolo su una riga indica la fine del DATA in SMTP
                print("[IPS] Fine mail. Avvio analisi completa del payload...")
                
                # Qui chiamiamo l'IA solo se necessario
                ja3_cat = state.get("ja3_category", "UNKNOWN")
                ja3_detail = state.get("ja3_detail", "Unknown")
                ja3_hash = state.get("ja3_hash", "") 
                
                try:
                    # Estrazione del testo in chiaro tramite il parser MIME
                    clean_text = extract_clear_text(state["buffer"])
                    
                    # Fallback logico: se il parsing fallisce o non trova text/plain, passiamo il buffer decodificato
                    if not clean_text:
                        print("[IPS] Attenzione: Nessun testo in chiaro estratto dal MIME. Invio buffer decodificato come fallback.")
                        clean_text = state["buffer"].decode('utf-8', errors='ignore')
                    else:
                        print(f"[IPS] Testo MIME estratto con successo ({len(clean_text)} caratteri).")

                    # Chiamata al nodo di inferenza
                    response = requests.post(
                        INFERENCE_URL, 
                        json={
                            "payload": clean_text,
                            "ja3_classification": ja3_cat,
                            "ja3_detail": ja3_detail,
                            "ja3_hash": ja3_hash
                        }, 
                        timeout=10,
                        verify=CERT_PATH # Usiamo il certificato TLS per la verifica della connessione al nodo di inferenza
                    )
                    
                    res = response.json()
                    label = res.get("label", "UNKNOWN") # La label restituita dall'IA

                    # Se la classificazione è AUTOMATION, applichiamo un tag specifico all'header Subject
                    if label == "AUTOMATION" or label == "MALWARE": # Aggiunto MALWARE nel caso in cui l'IA decida di non droppare ma solo taggare
                        ja3_info = state.get("ja3_category", "UNKNOWN")
                        tag = res.get("tag", "[AI-CHECK]")
                        
                        print(f"[IPS-TAGGING] Messaggio classificato come {label}. Inserimento tag in corso...")
                        
                        # Scorriamo tutti i pacchetti TCP che abbiamo messo in pausa
                        for msg in state["intercepted_messages"]:
                            if b"Subject: " in msg.content:
                                # Applichiamo la modifica direttamente ai byte del pacchetto corretto
                                msg.content = msg.content.replace(b"Subject: ", b"Subject: " + tag.encode() + b" ")
                                print("[IPS] Header Subject modificato con successo.")
                                break
                    else:
                        print(f"[IPS] Payload validato. Classificazione: {label}")

                except Exception as e:
                    print(f"[IPS-ERROR] Nodo IA irraggiungibile o errore: {e}")
                    
                    error_tag = b"[AI-UNVERIFIED]"
                    
                    # In caso di errore di comunicazione con il nodo di inferenza, applichiamo un tag di errore per indicare che il messaggio non è stato analizzato
                    for msg in state["intercepted_messages"]:
                        if b"Subject: " in msg.content:
                            msg.content = msg.content.replace(b"Subject: ", b"Subject: " + error_tag + b" ")
                            break


                state["in_data"] = False
                state["buffer"] = b""
                state["intercepted_messages"] = []

                
                if client_id in shared_state.ja3_memory:
                    del shared_state.ja3_memory[client_id]

                flow.resume()