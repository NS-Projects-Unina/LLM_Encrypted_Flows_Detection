import torch
import math
from fastapi import FastAPI, Request
from pydantic import BaseModel
from transformers import GPT2LMHeadModel, GPT2Tokenizer, RobertaForSequenceClassification, RobertaTokenizer, AutoModelForSequenceClassification, AutoTokenizer
import uvicorn
from peft import PeftModel

app = FastAPI()

# Modello di input per la richiesta al nodo di inferenza
class AlertData(BaseModel):
    payload: str
    ja3_classification: str
    ja3_detail: str
    ja3_hash: str

print("[AI NODE] Inizializzazione modelli in corso...")
# Caricamento e quantizzazione dei modelli all'avvio del server per ottimizzare le prestazioni durante le richieste
# Il modello GPT-2 viene usato per calcolare la Perplexity del testo, mentre il modello RoBERTa è un classificatore fine-tuned per distinguere tra testo umano e generato da AI, utile per identificare potenziali phishing o contenuti automatizzati.
# La quantizzazione dinamica di RoBERTa riduce l'uso di memoria e migliora la velocità di inferenza, rendendo il nodo di inferenza più efficiente senza una significativa perdita di accuratezza.
tokenizer_gpt2 = GPT2Tokenizer.from_pretrained("gpt2")
model_gpt2 = GPT2LMHeadModel.from_pretrained("gpt2")
model_gpt2.eval() # Impostiamo il modello in modalità eval per disabilitare dropout e altre funzionalità non necessarie durante l'inferenza

adapter_path = "/app/fine_tuned_ips_adapter"

tokenizer_roberta = AutoTokenizer.from_pretrained(adapter_path)
base_roberta = AutoModelForSequenceClassification.from_pretrained("roberta-base", num_labels=4)

model_roberta_peft = PeftModel.from_pretrained(base_roberta, adapter_path)
model_roberta_merged = model_roberta_peft.merge_and_unload()

# Utilizziamo torch.quantization.quantize_dynamic direttamente per compatibilità
model_roberta = torch.quantization.quantize_dynamic(
    model_roberta_merged, {torch.nn.Linear}, dtype=torch.qint8
)
model_roberta.eval()

print("[AI NODE] Modelli caricati e quantizzati.")

def calculate_perplexity(text: str) -> float: 
    
    encodings = tokenizer_gpt2(text, return_tensors="pt") 
    max_length = model_gpt2.config.n_positions
    stride = 512
    seq_len = encodings.input_ids.size(1)

    nlls = []
    prev_end_loc = 0
    for begin_loc in range(0, seq_len, stride):
        end_loc = min(begin_loc + max_length, seq_len)
        trg_len = end_loc - prev_end_loc
        input_ids = encodings.input_ids[:, begin_loc:end_loc]
        target_ids = input_ids.clone()
        target_ids[:, :-trg_len] = -100

        with torch.no_grad():
            outputs = model_gpt2(input_ids, labels=target_ids)
            neg_log_likelihood = outputs.loss

        nlls.append(neg_log_likelihood)
        prev_end_loc = end_loc
        if end_loc == seq_len:
            break

    ppl = torch.exp(torch.stack(nlls).mean()).item()
    if math.isnan(ppl):
        return float('inf')
    return ppl

def classify_roberta_multi(text: str) -> int:
    inputs = tokenizer_roberta(text, return_tensors="pt", truncation=True, max_length=512)
    with torch.no_grad():
        outputs = model_roberta(**inputs)
        # Prendiamo l'indice della classe con probabilità maggiore
        class_id = torch.argmax(outputs.logits, dim=-1).item()
    return class_id

@app.post("/analyze")
async def analyze_payload(data: AlertData):
    print(f"\n[AI NODE] Ricevuta richiesta di analisi. JA3 Classification: {data.ja3_classification}. Testo ricevuto: {data.payload} caratteri.")
    text = data.payload
    ja3_cat = data.ja3_classification
    
    if not text or len(text.strip()) < 150:
        return {"label": "NORMAL", "tag": ""}

    pp = calculate_perplexity(text)
    class_id = classify_roberta_multi(text) # 0:H-Legit, 1:H-Phish, 2:L-Legit, 3:L-Phish
    
    # I test hanno mostrato che 60 è troppo stringente. 115-120 è un valore più realistico per catturare GPT-4/Claude in italiano.
    is_ai_statistically = pp < 115.0

    result_label = "NORMAL"
    tag = ""

    # --- LOGICA DI OVERRIDE STATISTICO ---
    
    if is_ai_statistically:
        # Se la Perplexity è bassa, forziamo la categoria AUTOMATION.
        # Usiamo RoBERTa solo per distinguere se l'automazione è malevola o meno.
        result_label = "AUTOMATION"
        
        # Se RoBERTa rileva phishing (sia esso classe 1 o 3), marchiamo come AI-Phishing
        if class_id in [1, 3]:
            tag = "[AI-PHISHING-DETECTED]"
        else:
            tag = "[SUSPECT-AI-GENERATED]"
            
    else:
        # Se la Perplexity è alta (> 115), consideriamo il testo come UMANO.
        # Qui la classificazione di RoBERTa decide tra NORMAL e SUSPICIOUS.
        if class_id in [1, 3]:
            # Se RoBERTa vede phishing (anche se pensava fosse AI), su un testo 
            # ad alta PP lo trattiamo come phishing umano (Classe 1).
            result_label = "SUSPICIOUS"
            tag = "[POSSIBLE-PHISHING]"
        else:
            result_label = "NORMAL"
            tag = ""

    # Logica JA3 rimane come "ultima rete" per il traffico non testuale
    if ja3_cat == "AUTOMATION" and result_label == "NORMAL":
        result_label = "AUTOMATION"
        tag = "[BOT-TRAFFIC-DETECTED]"

    print(f"[AI NODE] Metriche - PP: {pp:.2f} | Classe Originale: {class_id} | Label Finale: {result_label} | Tag: {tag}")

    return {"label": result_label, "tag": tag}

# Avvio del server FastAPI
if __name__ == "__main__":
    
    uvicorn.run(app, host="0.0.0.0", port=5000)