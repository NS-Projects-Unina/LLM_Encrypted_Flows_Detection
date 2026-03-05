import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import ssl

PROXY_HOST = "10.0.0.5" 
PROXY_PORT = 465        

SENDER = "colleague@netsentinel.local"
RECIPIENT = "victim@netsentinel.local"

msg = MIMEMultipart()
msg['Subject'] = 'Project Update - NetSentinel Architecture Review'
msg['From'] = SENDER
msg['To'] = RECIPIENT


testo_legittimo = """Hey buddy, listen, I'm going to the park to watch the game later. Want to come with me? Please reply quickly, and I'll arrange to bring some beers.
                    """

msg.attach(MIMEText(testo_legittimo, 'plain', 'utf-8'))

try:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    print(f"[*] Sending legitimate communication to {PROXY_HOST}...")
    with smtplib.SMTP_SSL(PROXY_HOST, PROXY_PORT, context=context) as server:
        server.send_message(msg)
        print("[+] Message sent successfully.")
    
except Exception as e:
    print(f"\n[ERROR]: {e}")