# Questo script simula un attacco di phishing inviando un'email dannosa a una vittima attraverso un server proxy. 
# L'email contiene un messaggio di phishing che cerca di indurre la vittima a cliccare su un link e fornire informazioni sensibili.
# La mail viene inviata utilizzando il protocollo MIME e codificata in base64.
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.encoders import encode_base64
import ssl

PROXY_HOST = "10.0.0.5" 
PROXY_PORT = 465        

SENDER = "attacker@attacker.local"
RECIPIENT = "victim@netsentinel.local"

msg = MIMEMultipart()
msg['Subject'] = 'Email di prova'
msg['From'] = SENDER
msg['To'] = RECIPIENT

testo_phishing = """HURGENT WARNING!!! We have detected a serious error on your bank profile. Please you must update your details immediately to avoid losing access to your funds. Click here: http://secure-fast-web.it/login and enter your password and the code you receive via SMS. Do not waste time, you only have 10 minutes before the definitive closure of your bank account. Thanks security office."""

parte_testo = MIMEText(testo_phishing, 'plain', 'utf-8')

encode_base64(parte_testo)

msg.attach(parte_testo)

# In questo caso, utilizziamo SMTP_SSL per stabilire una connessione sicura con il server proxy sulla porta 465.
try:
    context = ssl.create_default_context()

    server = smtplib.SMTP_SSL(PROXY_HOST, PROXY_PORT, context=context)
    server.set_debuglevel(1) 
    
    server.send_message(msg)
    server.quit()
    
except Exception as e:
    print(f"\n[ERRORE] Impossibile inviare l'email: {e}")