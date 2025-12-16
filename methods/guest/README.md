# 🛠️ Sviluppo del Guest Code

Il **Guest Code** è la parte dell'applicazione che viene eseguita all'interno della zkVM. È qui che risiede la logica che vuoi provare crittograficamente.

## 📌 Concetti Chiave

Per garantire che il tuo programma sia compatibile con il sistema di verifica on-chain di Risc0Flow, devi seguire un flusso specifico di Input/Output.

### 1. Input (Dall'Host al Guest)
L'Host invia i dati al Guest come una sequenza di **byte grezzi** (ABI-encoded).
*   **Cosa fare**: Usa `env::stdin().read_to_end(&mut buffer)` per leggere i byte grezzi in un vettore, poi decodificali usando `Alloy` (es. `<(Type1, Type2)>::abi_decode(&buffer)`).
*   **Perché**: Questo permette di passare strutture dati complesse (tuple, array, struct) in modo standardizzato.

### 2. Logica Applicativa
Una volta decodificati i dati, puoi eseguire qualsiasi calcolo Rust puro.

### 3. Output (Dal Guest al Verifier)
Il risultato del calcolo deve essere reso "pubblico" (committato nel Journal) in un formato compatibile con uno smart contract Ethereum
*   **Formato Richiesto**: Una tupla ABI-encoded: `(string type_signature, bytes encoded_value)`.
    *   `type_signature`: La stringa che descrive il tipo Solidity (es. `"uint256"`, `"(uint256,address)"`).
    *   `encoded_value`: Il risultato vero e proprio, codificato in ABI.
*   **Cosa fare**: Usa `env::commit_slice` per inviare questa tupla codificata.

## 📂 Dove modificare il codice

Il file principale da modificare è:
`methods/guest/src/bin/guest.rs`

Troverai già un esempio funzionante che implementa questo pattern. Puoi usarlo come base e sostituire la logica di calcolo con la tua.

## 📦 Dipendenze Utili

Il template include già le librerie necessarie nel `Cargo.toml`:
- `risc0-zkvm`: Per interagire con la VM (`env::read`, `env::commit`).
- `alloy-sol-types`: Per la codifica/decodifica ABI compatibile con Ethereum.
