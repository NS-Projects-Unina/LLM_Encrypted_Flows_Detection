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


testo_legittimo = """Yo fam, listen up, I'm hittin' the park to peep the fixture later. You tryna pull up? Holla back ASAP and I'll clutch some cold ones for us. Real talk, you're still the same ol' geezer. I clocked you were moving to Alice and you kept it on the low. I'm always catching strays finding out from the grapevine. Sometimes I wonder if we’re actually ride-or-die or just capping.
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