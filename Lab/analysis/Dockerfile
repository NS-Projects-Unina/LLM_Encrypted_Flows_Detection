FROM python:3.10-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Creiamo la cartella di destinazione prima della copia
RUN mkdir -p /app/fine_tuned_ips_adapter

# Copiamo il contenuto della cartella locale nella cartella del container
COPY ./fine_tuned_ips_adapter/ /app/fine_tuned_ips_adapter/

COPY main.py .

EXPOSE 5000
# Usiamo il modulo python per avviare uvicorn
CMD ["python3", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5000"]