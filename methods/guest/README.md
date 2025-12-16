## 🛠️ Sviluppo Custom (Guest Code)

Per integrare la tua logica applicativa, devi modificare il codice del **Guest**.

### 1. Scrivi il Codice
Il codice sorgente del guest si trova in:
`methods/guest/src/bin/guest.rs`

Il framework utilizza un pattern specifico per input e output basato su **Alloy** (ABI encoding). Di seguito un esempio:

```rust
use alloy_sol_types::SolValue;
use risc0_zkvm::guest::env;
use std::io::Read;


fn my_computation(...)


fn main() {
    // 1. Leggi l'input (ABI-encoded dall'host) dall'ambiente env 
    let mut input_bytes = Vec::<u8>::new();
    env::stdin().read_to_end(&mut input_bytes).unwrap();

    // 2. Decodifica i parametri attesi (es. una tupla di tre valori U256)
    // Assicurati che i tipi corrispondano a quelli che passerai via CLI (--input <..., type_x, x, ...>)
    let (b, e, m) = <(U256, U256, U256)>::abi_decode(&input_bytes)  // esempio
        .expect("Errore decodifica input");                         // esempio

    // 3. Esegui la logica computazionale
    let result = my_computation(b, e, m); // esempio

    // 4. Committa il risultato nel formato standard del framework
    
    // Il framework si aspetta una coppia della forma: //
    // <string_solidity_type_name, bytes_encoded_data> = (type_info, raw_data)
    let type_info = "uint256"; // Tipo Solidity del risultato
    let raw_data = result.abi_encode(); // Encoding
    // Commit journal
    env::commit_slice(&(type_info, raw_data).abi_encode());
}
```

### 2. Build
Il framework ricompila automaticamente il guest quando esegui `host run`.