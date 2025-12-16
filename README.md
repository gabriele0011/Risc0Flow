# Risc0Flow

**Risc0Flow** è un framework per l'orchestrazione di applicazioni basate sulla zkVM di RISC Zero, progettato per offrire una completa automatizzazione delle operazioni e strumenti di sviluppo aggiuntivi, essenziali per sviluppare applicazioni con RISC Zero. Semplifica l'interazione con la zkVM offrendo un'interfaccia unificata per generare sessioni, produrre prove crittografiche e validarle su blockchain (ecosistema Ethereum), mantenendo ogni passaggio configurabile. 

È concepito come un **toolkit di operazioni** che possono essere eseguite singolarmente, combinate in un unico flusso continuo o disaccoppiate.

## 🚀 Funzionalità Principali

- **Architettura Modulare**: Esegue sessioni, proving e verifiche in modo indipendente o combinato.
- **Supporto Multi-Backend**: Genera prove **STARK** (veloci e verificabili localmente) o **Groth16** (compatte e verificabili on-chain).
- **Proving Locale**: Attualmente ottimizzato per carichi di lavoro CPU-bound eseguiti localmente.
- **Verifica On-Chain Integrata**: Interazione nativa con Ethereum (Anvil, Sepolia) tramite Alloy.
- **Metriche Dettagliate**: Esportazione opzionale (`--metrics`) di file CSV per l'analisi di performance (tempo, RAM, CPU, Gas) nelle varie fasi.

## 🧩 Architettura Modulare

Il framework è progettato per adattarsi a qualsiasi esigenza, permettendo sia un'esecuzione lineare che granulare:

1.  **Session & Debugging (`--session`)**: Esegue solo il programma guest scritto in Rust.
2.  **Proving (`--prove`)**: Genera le prove (STARK/Groth16). Può essere eseguito come step intermedio (salvando su disco la prova) o come parte di una pipeline continua.
3.  **Verifica (`--verify`)**: Valida la prova off-chain o on-chain. Può avvenire immediatamente dopo la fase di generazione della prova o in un secondo momento caricando il file (corrispondente alla prova esportata) dal disco.

## 📖 Scenari di Utilizzo

### 1. Sviluppo Rapido (solo logica Guest)
Verifica che il codice Rust del guest funzioni correttamente.
```bash
host run --input '<u256; 42>' --session
```

### 2. Pipeline Completa (All-in-One)
Genera la prova e verifica on-chain.
```bash
host run --input '<u256; 42>' --prove groth16 --source new --verify onchain --network sepolia --wallet $PRIVATE_KEY
```

### 3. Workflow Disaccoppiato (Proving Remoto / Verifica Differita)

**Step A: Generazione**
Genera la prova ed esporta su un file binario.
```bash
host run --input '<u256; 42>' --prove groth16
# Output salvato in: proofs/receipt_groth16_<timestamp>.bin
```

**Step B: Verifica**
Prendi il file generato e verifica la relativa prova on-chain.
```bash
host run --source file --proof-file proofs/receipt_groth16_<timestamp>.bin --verify onchain --network sepolia --wallet $PRIVATE_KEY
```

### 4. Stress Test On-Chain
Esegui verifiche multiple per testare la stabilità del contratto o calcolare il gas medio.
```bash
host run --source file --proof-file <FILE> --verify onchain --network anvil --n-runs 10 --metrics
```

## ️ Deploy

Il repository include script Bash per semplificare il deployment dei contratti di verifica:

- **`deploy_local.sh`**: Avvia un nodo Anvil locale (se non attivo) e deploya il contratto.
- **`deploy_sepolia.sh`**: Effettua il deploy del contratto sulla testnet Sepolia.

## 📊 Metriche

Se abilitato tramite il flag `--metrics`, tutti i dati di esecuzione vengono salvati automaticamente nella cartella `/metrics` con timestamp univoci:
- `session_metrics_*.csv`: Tempi di esecuzione e cicli utente.
- `proving_metrics_*.csv`: Tempi di proving, utilizzo RAM/CPU, dimensioni della prova.
- `tx_trace_metrics_*.csv`: Hash delle transazioni, gas used, gas price e stato di successo.
- `verify_metrics_*.csv`: Statistiche aggregate di verifica on-chain (gas medio, tempo medio, tasso di successo).

## 🛠️ Sviluppo Custom (Guest Code)

Per dettagli su come scrivere e integrare la tua logica applicativa nel Guest, consulta la documentazione dedicata in [methods/guest/README.md](methods/guest/README.md).


