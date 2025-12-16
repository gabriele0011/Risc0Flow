# Risc0Flow

**Risc0Flow** è un framework per l'orchestrazione di applicazioni basate su RISC Zero zkVM, progettato per offrire massima flessibilità e controllo nel ciclo di vita delle Zero-Knowledge Proofs. Semplifica l'interazione con la zkVM offrendo un'interfaccia unificata per generare sessioni, produrre prove crittografiche e validarle su blockchain, mantenendo ogni passaggio opzionale e configurabile.

È concepito come un **toolkit di operazioni** che possono essere eseguite singolarmente, combinate in un unico flusso continuo, o disaccoppiate nel tempo e nello spazio.

## 🚀 Funzionalità Principali

- **Architettura Modulare**: Esegui sessioni, proving e verifiche in modo indipendente o combinato.
- **Supporto Multi-Backend**: Genera prove **STARK** (veloci) o **Groth16** (compatte e verificabili on-chain).
- **Proving Locale**: Attualmente ottimizzato per carichi di lavoro CPU-bound eseguiti localmente.
- **Verifica On-Chain Integrata**: Interazione nativa con Ethereum (Anvil, Sepolia) tramite Alloy.
- **Metriche Dettagliate**: Esportazione opzionale (`--metrics`) di file CSV per l'analisi di performance (tempo, RAM, CPU, Gas) nella varie fasi.
- **Dev Mode**: Mock Prover per testare istantaneamente l'integrazione degli smart contract senza attendere i tempi di proving.

## 🧩 Architettura Modulare

Il framework è progettato per adattarsi a qualsiasi esigenza, permettendo sia un'esecuzione lineare che granulare:

1.  **Session & Debugging (`--session`)**: Esegui solo la logica del Guest per testare l'output e misurare i *user cycles*.
2.  **Proving (`--prove`)**: Genera le prove (STARK/Groth16). Può essere eseguito come step intermedio (salvando su disco) o come parte di una pipeline continua.
3.  **Verifica (`--verify`)**: Valida la prova off-chain o on-chain. Può avvenire immediatamente dopo il proving (in memoria) o in un secondo momento caricando il file da disco.

## 📖 Scenari di Utilizzo

### 1. Sviluppo Rapido (Logica Guest)
Verifica che il codice Rust del guest funzioni correttamente senza attendere il proving.
```bash
host run --input '<u256; 42>' --session
```

### 2. Pipeline Completa (All-in-One)
Genera la prova e verificala immediatamente on-chain in un unico comando.
```bash
host run --input '<u256; 42>' --prove groth16 --source new --verify onchain --network sepolia --wallet $PRIVATE_KEY
```

### 3. Workflow Disaccoppiato (Proving Remoto / Verifica Differita)

**Step A: Generazione**
Genera la prova e salvala su file.
```bash
host run --input '<u256; 42>' --prove groth16
# Output salvato in: proofs/receipt_groth16_<timestamp>.bin
```

**Step B: Verifica**
Prendi il file generato e verificalo on-chain quando necessario.
```bash
host run --source file --proof-file proofs/receipt_groth16_<timestamp>.bin --verify onchain --network sepolia --wallet $PRIVATE_KEY
```

### 4. Stress Test On-Chain
Esegui verifiche multiple per testare la stabilità del contratto o calcolare il gas medio.
```bash
host run --source file --proof-file <FILE> --verify onchain --network anvil --n-runs 10
```

## �️ Automazione Deploy

Il repository include script Bash per semplificare il deployment dei contratti di verifica:

- **`deploy_local.sh`**: Avvia un nodo Anvil locale (se non attivo) e deploya il contratto.
- **`deploy_sepolia.sh`**: Effettua il deploy del contratto sulla testnet Sepolia (attualmente richiede variabili d'ambiente configurate).

## �📊 Metriche

Se abilitato tramite il flag `--metrics`, tutti i dati di esecuzione vengono salvati automaticamente nella cartella `/metrics` con timestamp univoci:
- `session_metrics_*.csv`: Tempi di esecuzione e cicli utente.
- `proving_metrics_*.csv`: Tempi di proving, utilizzo RAM/CPU, dimensioni della prova.
- `tx_trace_metrics_*.csv`: Hash delle transazioni, gas used, gas price e stato di successo.
- `verify_metrics_*.csv`: Statistiche aggregate di verifica on-chain (gas medio, tempo medio, tasso di successo).
