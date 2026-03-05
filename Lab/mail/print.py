#!/usr/bin/env python3
import sys
import email
from email import policy

# Legge l'intero messaggio dallo standard input
raw_email = sys.stdin.read()
msg = email.message_from_string(raw_email, policy=policy.default)

print("\n" + "="*50)
print(f"[*] NUOVA MAIL RICEVUTA DA: {msg['From']}")
print(f"[*] DESTINATARIO: {msg['To']}")
print(f"[*] OGGETTO: {msg['Subject']}")
print("-" * 50)

# Iterazione sulle parti del messaggio per gestire MIME
if msg.is_multipart():
    for part in msg.walk():
        content_type = part.get_content_type()
        content_disposition = str(part.get("Content-Disposition"))

        if content_type == "text/plain" and "attachment" not in content_disposition:
            # get_payload(decode=True) gestisce automaticamente la decodifica Base64/Quoted-Printable
            payload = part.get_payload(decode=True).decode('utf-8', errors='replace')
            print(f"[CORPO DECIFRATO - {content_type}]:\n{payload}")
else:
    payload = msg.get_payload(decode=True).decode('utf-8', errors='replace')
    print(f"[CORPO DECIFRATO]:\n{payload}")

print("="*50 + "\n")