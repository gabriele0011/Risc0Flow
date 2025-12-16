// alloy è un toolkit Ethereum (types, RPC, signing)
use alloy::{
    network::EthereumWallet, providers::ProviderBuilder, signers::local::PrivateKeySigner,
    sol_types::SolValue,
};
use alloy_primitives::{Address, Bytes};
use alloy_primitives::U256;

// gestione errori
use anyhow::{Context, Result};

// elf binary del guest 
use methods::{GUEST_ELF, GUEST_ID};

// funzione helper per impacchettare una receipt da verificare onchain
use risc0_ethereum_contracts::encode_seal;
// include funzionalita della zkvm
use risc0_zkvm::{
    default_prover, ExecutorEnv, ExecutorImpl, ProverOpts, VerifierContext, Receipt, Session,
};

// ABI interface generata via alloy `sol!`
alloy::sol!(
    #[sol(rpc, all_derives)]
    "../contracts/IContract.sol"
);

// usato per rpc_ur
use url::Url;

// include std esteso
use std::{
    fs::File,
    io::{Read, Write},
    time::Instant,
    error::Error,
    fmt,
    str::FromStr,
};

// Modulo per le metriche di sistema
mod system_metrics;
use system_metrics::MetricsMonitor;


/* 
*   Sistema di validazione dei tipi
*/
#[derive(Debug, PartialEq)]
pub enum ParseError {
    UnknownType(String),           // il tipo dichiarato non è supportato
    InvalidDataFormat(String),      // i dati non rispettano il formato dichiarato
}

// validazione dell'input
#[derive(Debug, PartialEq, Clone)]
pub enum ValidatedSolData {
    Uint256(U256),
    Uint256Triple(U256, U256, U256),
    String(String),
    Bytes(Vec<u8>),
    Bool(bool),
    Address(Address),
    BytesN(Vec<u8>, usize), // (value, N) con 1<=N<=32
}

// Struttura per input tipizzato nel formato <type_data, data> 
#[derive(Debug, Clone)]
struct TypedInput {
    type_name: String,
    data: String,
    validated: ValidatedSolData,
}


/*  
*   Importa le derive di Clap necessarie per definire la CLI in modo dichiarativo: 
*   Parser crea il parser principale e l’help/usage, Subcommand mappa gli enum ai sottocomandi, 
*   Args descrive gli argomenti dei subcomandi, e ValueEnum consente enum come valori ammessi per le 
*   opzioni con validazione automatica eliminando il bisogno di parsing manuale.
*/
use clap::{Args, Parser, Subcommand, ValueEnum};

// rappresenta i backend di proving supportati da CLI
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Backend {
    #[value(name = "stark")] Stark,
    #[value(name = "groth16")] Groth16,
}

// indica l'origine della prova da verificare. Le possibilità sono: generata in questa sessione o importata 
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum VerifySource { #[value(name = "new")] New, #[value(name = "file")] File }

// indica il tipo di verifica: offchain o onchain
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum VerifyMode { #[value(name = "offchain")] Offchain, #[value(name = "onchain")] Onchain }

// specifica quale rete usare durante la verifica: anvil o sepolia
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Network { #[value(name = "anvil")] Anvil, #[value(name = "sepolia")] Sepolia }


/*
*   Configurazioni specifiche per profilo di rete on-chain
*/

#[derive(Debug, Clone)]
struct AnvilConfig {
    chain_id: u64,
    rpc_url: Url,
    contract: Address,
    signer_private_key: String,
}

#[derive(Debug, Clone)]
struct SepoliaConfig {
    chain_id: u64,
    rpc_url: Url,
    contract: Address,
    wallet_private_key: String,
}

#[derive(Debug, Clone)]
enum ChainProfile {
    Anvil(AnvilConfig),
    Sepolia(SepoliaConfig),
}

use std::path::Path;

/*
* definizione CLI e parsing
*/

// definizione della "interfaccia" pubblica della CLI 
#[derive(Parser, Debug)]
#[command(
    name = "host",
    about = "CLI non interattiva per orchestrare sessione, proving e verifica (acquisizione parametri)",
    version,
    long_about = "Comando unico: run. Formato input: <tipo_par_1, ..., tipo_par_n; par_1, ..., par_n>.\n\
    Backends: stark, groth16. Verifica: prima scegli la sorgente (new | file), poi il modo (offchain | onchain).\n\
    Se onchain, specifica la rete: anvil | sepolia (su sepolia serve --wallet).",
    help_template = "{name} {version}\n\n{about}\n\nUSO:\n    {usage}\n\nCOMANDI:\n{subcommands}\nOPZIONI GLOBALI:\n{options}\n\nESEMPI:\n  # Sessione\n  host run --input '<u256; 0x01>' --session\n  # Prova con 2 backend + metriche\n  host run --input '<u256; 0x01>' --prove stark groth16 --metrics\n  # Verifica locale offchain di una prova da file\n  host run --source file --proof-file receipts/prova.json --verify offchain\n  # Verifica on-chain in anvil di una prova da file\n  host run --source file --proof-file receipts/prova.json --verify onchain --network anvil\n  # Verifica on-chain in sepolia di una prova appena generata\n  host run --input '<u256; 0x02>' --prove groth16 --source new --verify onchain --network sepolia --wallet 0xYOUR_PRIVATE_KEY\n\nSuggerimenti:\n  - Prima scegli la sorgente prova: --source new (con --input e --prove) oppure --source file (con --proof-file)\n  - Poi scegli il modo: --verify offchain | onchain; se onchain serve anche --network anvil|sepolia\n  - --wallet è richiesto solo se --verify onchain --network sepolia\n",
    subcommand_required = true,
    arg_required_else_help = true
)]

// struct che incapsula il set di sottocomandi Comands disponibili
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

// Run(RunCmd) definisce il sottocomando run: raggruppa tutti i flag della pipeline
#[derive(Subcommand, Debug)]
enum Commands {
    #[command(
        about = "Esegue la pipeline configurata (sessione, proving, verifica) in una riga",
        long_about = "Combina le operazioni desiderate in un'unica esecuzione: --session, --prove, --verify.",
        after_help = "Esempi:\n  host run --input '<u256; 0x01>' --session\n  host run --input '<u256; 0x01>' --prove stark groth16\n  host run --verify offchain --source file --proof-file receipts/prova.json\n  host run --source file --proof-file receipts/prova.json --verify onchain --network anvil\n  host run --input '<u256; 0x02>' --prove groth16 --source new --verify onchain --network sepolia --wallet 0xYOUR_PRIVATE_KEY"
    )]
    Run(RunCmd),
}

// raccoglie tutti i flag e le opzioni necessari a descrivere
// una pipeline composta (sessione, proving, verifica).
#[derive(Args, Debug)]
struct RunCmd {
    /// Stringa: <tipo_par_1, ..., tipo_par_n; par_1, ..., par_n>
    #[arg(long, value_name = "INPUT_SPEC")]
    input: Option<String>,

    /// Genera una sessione
    #[arg(long, default_value_t = false)]
    session: bool,

    /// Seleziona backend di prova (uno o più): stark, groth16
    #[arg(long, value_enum, num_args = 1.., value_name = "BACKEND")]
    prove: Vec<Backend>,

    /// Modo di verifica: offchain (locale) | onchain
    #[arg(long, value_enum, value_name = "MODE")]
    verify: Option<VerifyMode>,

    /// Rete on-chain: anvil | sepolia (richiesto se --verify onchain)
    #[arg(long, value_enum, value_name = "NETWORK")]
    network: Option<Network>,

    /// Origine prova: new | file
    #[arg(long, value_enum, value_name = "SOURCE")]
    source: Option<VerifySource>,

    /// File prova (richiesto se --source file)
    #[arg(long, value_name = "FILE")]
    proof_file: Option<String>,

    /// Wallet (richiesto se --verify onchain --network sepolia)
    #[arg(long, value_name = "WALLET")]
    wallet: Option<String>,

    /// Abilita metriche
    #[arg(long, default_value_t = false)]
    metrics: bool,
}


// ##########################################################################
// GESTIONE DELL'INPUT
// ##########################################################################
/*
*   valida le combinazioni di flag passate a host run
*   e blocca configurazioni ambigue o incomplete, restituendo errori specifici
*/
fn validate_run(cmd: &RunCmd) -> Result<()> {
    use anyhow::{bail, ensure};

    // Almeno un'operazione selezionata
    let any_op = cmd.session || !cmd.prove.is_empty() || cmd.verify.is_some();
    ensure!(any_op, "Nessuna operazione selezionata: usa almeno uno tra --session, --prove, --verify");

    // --verify richiede anche --source
    if cmd.verify.is_some() && cmd.source.is_none() {
        bail!("--verify richiede anche --source (new|file)");
    }

    // --verify onchain richiede --network
    if matches!(cmd.verify, Some(VerifyMode::Onchain)) && cmd.network.is_none() {
        bail!("--verify onchain richiede --network (anvil|sepolia)");
    }

    // --network non ammessa se verify=offchain o assente
    if (matches!(cmd.verify, Some(VerifyMode::Offchain)) || cmd.verify.is_none()) && cmd.network.is_some() {
        bail!("--network è valido solo con --verify onchain");
    }

    // --verify con --source new richiede almeno una prova richiesta nello stesso comando
    if matches!(cmd.source, Some(VerifySource::New)) && cmd.verify.is_some() && cmd.prove.is_empty() {
        bail!("Verifica con --source new richiede anche --prove <BACKEND>... (nessuna prova richiesta)");
    }

    // --input richiesto per session/prove/source=new
    let needs_input = cmd.session || !cmd.prove.is_empty() || matches!(cmd.source, Some(VerifySource::New));
    if needs_input {
        let has_input = cmd.input.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false);
        ensure!(has_input, "--input è richiesto per --session, --prove o --source new");
    }

    // --proof-file richiesto per source=file
    if matches!(cmd.source, Some(VerifySource::File)) {
        let has_file = cmd.proof_file.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false);
        ensure!(has_file, "--proof-file è richiesto quando --source file");
    }

    // --wallet richiesto per onchain sepolia
    if matches!(cmd.verify, Some(VerifyMode::Onchain)) && matches!(cmd.network, Some(Network::Sepolia)) {
        let has_wallet = cmd.wallet.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false);
        ensure!(has_wallet, "--wallet è richiesto quando --verify onchain --network sepolia");
    }

    // Vincoli aggiuntivi per evitare combinazioni ridondanti/ambigue
    // 1) Con source=new non si deve passare --proof-file
    if matches!(cmd.source, Some(VerifySource::New)) && cmd.proof_file.is_some() {
        bail!("Con --source new non usare --proof-file (vale solo per --source file)");
    }

    // 2) Con source=file non si deve passare --input (non richiesto, potenzialmente ambiguo)
    if matches!(cmd.source, Some(VerifySource::File)) && cmd.input.is_some() {
        bail!("Con --source file non usare --input (serve solo per --source new o per prove/session)");
    }

    // 3) Con verify=offchain non si deve passare --wallet
    if matches!(cmd.verify, Some(VerifyMode::Offchain)) && cmd.wallet.is_some() {
        bail!("--wallet è valido solo con --verify onchain --network sepolia (non con offchain)");
    }

    // 4) Con verify=onchain e network=anvil non si deve passare --wallet
    if matches!(cmd.verify, Some(VerifyMode::Onchain)) && matches!(cmd.network, Some(Network::Anvil)) && cmd.wallet.is_some() {
        bail!("--wallet è valido solo con --verify onchain --network sepolia (non con anvil)");
    }

    Ok(())
}


//typechecking
impl Error for ParseError {}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseError::UnknownType(type_str) => {
                write!(f, "Tipo sconosciuto: '{}'", type_str)
            }
            ParseError::InvalidDataFormat(err_msg) => {
                write!(f, "Formato dati non valido: {}", err_msg)
            }
        }
    }
}

/*
*   La seguente funzione è il parser/validatore centrale dei tipi Solidity dichiarati nell’input tipizzato; 
*   normalizza la dichiarazione, riconosce casi speciali 
*   (la tripla uint256, uint<M>, bytes/bytesN, address, string, bool), 
*   valida formato e range, e restituisce un ValidatedSolData pronto per l’ABI encoding. 
*   In caso di errore, ritorna ParseError con messaggi mirati.
*/

pub fn parse_and_validate_typed(typedata: &str, data: &str) -> Result<ValidatedSolData, ParseError> {
    // Normalizzazione per supportare anche formati senza parentesi per triple di uint256
    let t_clean = typedata.trim();
    let t_inner = if t_clean.starts_with('(') && t_clean.ends_with(')') {
        &t_clean[1..t_clean.len()-1]
    } else {
        t_clean
    };

    // Riconosci "uint256,uint256,uint256" (con o senza parentesi, con spazi)
    let items: Vec<&str> = t_inner.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    if items.len() == 3 && items.iter().all(|&s| s == "uint256") {
        // Parsing dei dati per la tripla (accetta con o senza parentesi)
        let inner_vals = data.trim().trim_matches(|c| c == '(' || c == ')');
        let parts: Vec<&str> = inner_vals.split(',').map(|s| s.trim()).collect();
        if parts.len() != 3 {
            return Err(ParseError::InvalidDataFormat(
                format!("Attesi 3 valori per la tupla, trovati {}", parts.len())
            ));
        }
        let b = U256::from_str(parts[0])
            .map_err(|e| ParseError::InvalidDataFormat(format!("base non valida: {}", e)))?;
        let e = U256::from_str(parts[1])
            .map_err(|e| ParseError::InvalidDataFormat(format!("esponente non valido: {}", e)))?;
        let m = U256::from_str(parts[2])
            .map_err(|e| ParseError::InvalidDataFormat(format!("modulo non valido: {}", e)))?;
        return Ok(ValidatedSolData::Uint256Triple(b, e, m));
    }

    match typedata {
        "uint256" => {
            U256::from_str(data)
                .map(ValidatedSolData::Uint256)
                .map_err(|e| ParseError::InvalidDataFormat(format!("uint256 non valido: {}", e)))
        },

        // La tripla è già gestita sopra in maniera più permissiva

        "string" => {
            if data.is_empty() {
                Err(ParseError::InvalidDataFormat("La stringa non può essere vuota".to_string()))
            } else {
                Ok(ValidatedSolData::String(data.to_string()))
            }
        },

        "bytes" => {
            if !data.starts_with("0x") {
                return Err(ParseError::InvalidDataFormat("I bytes devono iniziare con 0x".to_string()));
            }
            hex::decode(&data[2..])
                .map(ValidatedSolData::Bytes)
                .map_err(|e| ParseError::InvalidDataFormat(format!("bytes non validi: {}", e)))
        },

        "bool" => {
            match data.to_lowercase().as_str() {
                "true" | "1" => Ok(ValidatedSolData::Bool(true)),
                "false" | "0" => Ok(ValidatedSolData::Bool(false)),
                _ => Err(ParseError::InvalidDataFormat("bool deve essere true/false/1/0".to_string()))
            }
        },

        _ => {
            // uint<M>
            if let Some(rest) = typedata.strip_prefix("uint") {
                if rest.is_empty() {
                    return Err(ParseError::InvalidDataFormat("uint senza dimensione: usa uint256 o uint<M>".to_string()));
                }
                let bits: u16 = rest.parse().map_err(|_| ParseError::InvalidDataFormat("Dimensione di uint non valida".to_string()))?;
                if bits % 8 != 0 || bits == 0 || bits > 256 {
                    return Err(ParseError::InvalidDataFormat("uint<M>: M deve essere multiplo di 8, 8..=256".to_string()));
                }
                let val = U256::from_str(data).map_err(|e| ParseError::InvalidDataFormat(format!("uint{} non valido: {}", bits, e)))?;
                if bits < 256 {
                    let bound = U256::from(1u64) << (bits as u32);
                    if val >= bound {
                        return Err(ParseError::InvalidDataFormat(format!("Valore fuori range per uint{}", bits)));
                    }
                }
                // Nota: per l'encoding tratteremo come uint256 (ABI word) lato host
                return Ok(ValidatedSolData::Uint256(val));
            }

            // bytesN (1..=32)
            if let Some(rest) = typedata.strip_prefix("bytes") {
                if !rest.is_empty() {
                    let n: usize = rest.parse().map_err(|_| ParseError::InvalidDataFormat("bytesN: N non valido".to_string()))?;
                    if n == 0 || n > 32 {
                        return Err(ParseError::InvalidDataFormat("bytesN: N deve essere 1..=32".to_string()));
                    }
                    if !data.starts_with("0x") { return Err(ParseError::InvalidDataFormat("bytesN deve iniziare con 0x".to_string())); }
                    let hex_part = &data[2..];
                    if hex_part.len() != n * 2 {
                        return Err(ParseError::InvalidDataFormat(format!("bytes{}: lunghezza attesa {} hex chars, trovati {}", n, n*2, hex_part.len())));
                    }
                    let v = hex::decode(hex_part).map_err(|e| ParseError::InvalidDataFormat(format!("bytes{} non validi: {}", n, e)))?;
                    return Ok(ValidatedSolData::BytesN(v, n));
                }
            }

            // address
            if typedata == "address" {
                let addr = Address::from_str(data).map_err(|_| ParseError::InvalidDataFormat("address non valido (atteso 0x + 40 hex)".to_string()))?;
                return Ok(ValidatedSolData::Address(addr));
            }

            Err(ParseError::UnknownType(typedata.to_string()))
        },
    }
}


fn parse_typed_input(spec: &str) -> Result<TypedInput, ParseError> {
    let trimmed = spec.trim();
    if !trimmed.starts_with('<') || !trimmed.ends_with('>') {
        return Err(ParseError::InvalidDataFormat("Input deve essere racchiuso tra < e >".into()));
    }
    let inner = &trimmed[1..trimmed.len()-1];
    let parts: Vec<&str> = inner.splitn(2, ';').collect();
    if parts.len() != 2 {
        return Err(ParseError::InvalidDataFormat("Formato deve essere <tipo; dati>".into()));
    }
    let type_name = parts[0].trim();
    let data = parts[1].trim();
    if type_name.is_empty() || data.is_empty() {
        return Err(ParseError::InvalidDataFormat("Tipo o dati vuoti".into()));
    }
    let validated = parse_and_validate_typed(type_name, data)?;
    Ok(TypedInput { type_name: type_name.to_string(), data: data.to_string(), validated })
}




// ##########################################################################
// GENERAZIONE SESSIONE
// ##########################################################################

// Genera una sessione eseguendo il guest con l'input ABI-encoded.
// Ritorna la Session e, se metrics=true, registra su CSV: input_spec,time_ms,user_cycles
pub fn exec_session_stub(encoded_input: &[u8], input_label: &str, metrics: bool) -> Result<Session> {
    
    println!("generazione session in corso...");
    let env = ExecutorEnv::builder()
        .write_slice(encoded_input)
        .build()?;

    let t0_exec_session = Instant::now();
    let mut exec_once = ExecutorImpl::from_elf(env, GUEST_ELF)?;
    let session_once: Session = exec_once.run()?;
    let t_exec_session: u128 = t0_exec_session.elapsed().as_millis();
    let user_cycles_once: u64 = session_once.user_cycles;

    if metrics {
        let mut exec_log = File::options()
            .append(true)
            .create(true)
            .open("session_metrics.csv")?;
        if exec_log.metadata()?.len() == 0 {
            writeln!(exec_log, "input_spec,time_ms,user_cycles")?;
        }
        // CSV-safe: racchiudi tra doppi apici e raddoppia eventuali apici interni
        let safe_label = input_label.replace('"', "\"\"");
        writeln!(exec_log, "\"{}\",{},{}", safe_label, t_exec_session, user_cycles_once)?;
    }
    println!("generazione session terminata con successo");

    Ok(session_once)
}

/*
// sostituita dalla chiamata generate_proof_for_backend
fn exec_prove_stub(input: &str, backend: Backend, metrics: bool) {
    let backend_name = match backend { Backend::Stark => "stark", Backend::Groth16 => "groth16" };
    println!("[STUB] PROVE start: backend={}, input={:?}, metrics={}", backend_name, input, metrics);
    println!("[STUB] PROVE done: backend={}", backend_name);
}
*/


// ##########################################################################
// GENERAZIONE DELLA PROVA
// ##########################################################################

// Misura e genera una prova per un backend specifico riutilizzando una Session esistente.
// Registra metriche dettagliate (tempo, dimensioni seal/journal/receipt serializzato) se metrics=true.
fn generate_proof_for_backend(
    backend: Backend,
    encoded_input: &[u8], // input già ABI-encoded
    metrics: bool,
) -> Result<Receipt> {
    use anyhow::Context;

    // Nome backend per logging/metriche
    let backend_name: &str = match backend { Backend::Stark => "stark", Backend::Groth16 => "groth16" };

    // Seleziona le opzioni del prover in base al backend richiesto
    let prover_opts = match backend {
        Backend::Stark => ProverOpts::succinct(),
        Backend::Groth16 => ProverOpts::groth16(),
    };

    // Env nuovo per la fase di proving
    let env = ExecutorEnv::builder()
        .write_slice(encoded_input)
        .build()
        .context("Impossibile costruire l'ExecutorEnv per il proving")?;

    let t0 = Instant::now();
    
    // Avvia monitoraggio risorse se metriche attive
    let monitor = if metrics { Some(MetricsMonitor::start()) } else { None };

    let prove_result = default_prover()
        .prove_with_ctx(env, &VerifierContext::default(), GUEST_ELF, &prover_opts)
        .context("Errore nella generazione della prova")?;
    
    // Ferma monitoraggio e raccogli dati
    let sys_metrics = if let Some(m) = monitor {
        Some(m.stop())
    } else {
        None
    };

    let elapsed_ms = t0.elapsed().as_millis();

    let receipt = prove_result.receipt;

    // SALVATAGGIO PROVA SU FILE (per testing verifica from-file)
    let receipt_bytes = bincode::serialize(&receipt).context("Serializzazione receipt fallita")?;
    std::fs::write("receipt.bin", &receipt_bytes).context("Salvataggio receipt.bin fallito")?;
    println!("Prova salvata in 'receipt.bin'");

    if metrics {
        // CSV proving_metrics.csv: backend,phase,time_ms,seal_size,journal_len,receipt_bincode_len,peak_ram_kb,avg_cpu_pct,max_cpu_pct
        let mut file = File::options().append(true).create(true).open("proving_metrics.csv")?;
        if file.metadata()?.len() == 0 {
            writeln!(file, "backend,phase,time_ms,seal_size,journal_len,receipt_bincode_len,peak_ram_kb,avg_cpu_pct,max_cpu_pct")?;
        }
        let seal_size = receipt.seal_size();
        let journal_len = receipt.journal.bytes.len();
        let receipt_ser_len = bincode::serialize(&receipt).map(|v| v.len()).unwrap_or(0);
        
        let (ram, avg_cpu, max_cpu) = if let Some(sm) = sys_metrics {
            (sm.peak_ram_kb, sm.avg_cpu_usage, sm.max_cpu_usage)
        } else {
            (0, 0.0, 0.0)
        };

        writeln!(
            file,
            "{},{},{},{},{},{},{},{:.2},{:.2}",
            backend_name,
            "prove",
            elapsed_ms,
            seal_size,
            journal_len,
            receipt_ser_len,
            ram,
            avg_cpu,
            max_cpu
        )?;
    }

    println!("Prova generata: backend={}, seal_bytes={}, journal_bytes={}", backend_name, receipt.seal_size(), receipt.journal.bytes.len());
    Ok(receipt)
}



// ##########################################################################
// PROCEDURE DI VERIFICA 
// ##########################################################################


// Helper per trovare l'indirizzo del contratto deployato su Anvil
fn find_anvil_contract_address() -> Option<Address> {
    let potential_paths = [
        "broadcast/Deploy.s.sol/31337/run-latest.json",
        "../broadcast/Deploy.s.sol/31337/run-latest.json",
    ];

    for path_str in potential_paths {
        let path = Path::new(path_str);
        if path.exists() {
            if let Ok(file) = File::open(path) {
                if let Ok(json) = serde_json::from_reader::<_, serde_json::Value>(file) {
                    // Cerca nelle transazioni la prima che ha un contractAddress
                    if let Some(transactions) = json.get("transactions").and_then(|t| t.as_array()) {
                        for tx in transactions {
                            // Filtra per nome del contratto "Contract"
                            if let Some(name) = tx.get("contractName").and_then(|n| n.as_str()) {
                                if name == "Contract" {
                                    if let Some(addr_str) = tx.get("contractAddress").and_then(|v| v.as_str()) {
                                        if let Ok(addr) = Address::from_str(addr_str) {
                                            println!("Indirizzo contratto Contract estratto: {}", addr);
                                            return Some(addr);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

// Helper per trovare l'indirizzo del contratto deployato su Sepolia
fn find_sepolia_contract_address() -> Option<Address> {
    let potential_paths = [
        "broadcast/Deploy.s.sol/11155111/run-latest.json",
        "../broadcast/Deploy.s.sol/11155111/run-latest.json",
    ];

    for path_str in potential_paths {
        let path = Path::new(path_str);
        if path.exists() {
            if let Ok(file) = File::open(path) {
                if let Ok(json) = serde_json::from_reader::<_, serde_json::Value>(file) {
                    // Cerca nelle transazioni la prima che ha un contractAddress
                    if let Some(transactions) = json.get("transactions").and_then(|t| t.as_array()) {
                        for tx in transactions {
                            // Filtra per nome del contratto "Contract"
                            if let Some(name) = tx.get("contractName").and_then(|n| n.as_str()) {
                                if name == "Contract" {
                                    if let Some(addr_str) = tx.get("contractAddress").and_then(|v| v.as_str()) {
                                        if let Ok(addr) = Address::from_str(addr_str) {
                                            println!("Indirizzo contratto Sepolia estratto da broadcast: {}", addr);
                                            return Some(addr);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}


fn build_chain_profile(cmd: &RunCmd) -> Result<Option<ChainProfile>> {
    
    if !matches!(cmd.verify, Some(VerifyMode::Onchain)) {
        return Ok(None);
    }

    let network = match cmd.network {
        Some(n) => n,
        None => return Ok(None), // già validato prima
    };

    match network {
        Network::Anvil => {
            // richiede variabili globali non ancora gestite: usiamo placeholder / default
            // NOTA: qui in assenza di global flags usiamo default convenzionali
            let chain_id = 31337u64;
            let rpc_url = Url::parse("http://localhost:8545").context("RPC URL default anvil non valido")?;
            
            // Tenta di recuperare l'indirizzo automaticamente dal file di broadcast di Foundry
            let contract = find_anvil_contract_address()
                .or_else(|| std::env::var("MOD_EXP_CONTRACT_ADDRESS").ok().and_then(|s| Address::from_str(&s).ok()))
                .context("Indirizzo contratto non trovato! Assicurati di aver fatto il deploy (broadcast/Deploy.s.sol/31337/run-latest.json) o imposta MOD_EXP_CONTRACT_ADDRESS.")?;

            println!("Contratto rilevato automaticamente: {}", contract);

            // private key: per anvil usiamo sempre la chiave di default (Account 0)
            // Questa chiave è deterministica per la mnemonic di default di Anvil
            let signer_private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string();
            Ok(Some(ChainProfile::Anvil(AnvilConfig { chain_id, rpc_url, contract, signer_private_key })))
        }
        Network::Sepolia => {
            let chain_id = 11155111u64;
            
            // Tenta di recuperare RPC URL da env, altrimenti usa default
            let rpc_url_str = std::env::var("SEPOLIA_RPC_URL")
                .unwrap_or_else(|_| "https://eth-sepolia.g.alchemy.com/v2/OKLxGgiSdmgSIz9G5FuKx".to_string());
            let rpc_url = Url::parse(&rpc_url_str).context("RPC URL sepolia non valido")?;

            // Tenta di recuperare l'indirizzo da env o broadcast, fallback hardcoded
            let contract = std::env::var("SEPOLIA_CONTRACT_ADDRESS")
                .ok()
                .and_then(|s| Address::from_str(&s).ok())
                .or_else(find_sepolia_contract_address)
                .or_else(|| Address::from_str("0xb2a3D05EF6FBBbcd71933bb2239b5954D242f833").ok())
                .context("Indirizzo contratto Sepolia non trovato! Imposta SEPOLIA_CONTRACT_ADDRESS o esegui il deploy.")?;

            println!("Contratto Sepolia configurato: {}", contract);
            println!("RPC URL: {}", rpc_url);

            // sepolia richiede --wallet (già validato) → qui lo recuperiamo
            let wallet_private_key = cmd.wallet.clone().expect("wallet già validato ma assente");
            Ok(Some(ChainProfile::Sepolia(SepoliaConfig { chain_id, rpc_url, contract, wallet_private_key })))
        }
    }
}



//verifica on chain con file
 fn exec_verify_onchain_from_file(path: &str, profile: &ChainProfile, metrics: bool) {
    println!("Caricamento prova da file: {}", path);

    // Leggi il file
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Errore apertura file prova: {}", e);
            return;
        }
    };
    let mut buffer = Vec::new();
    if let Err(e) = file.read_to_end(&mut buffer) {
        eprintln!("Errore lettura file prova: {}", e);
        return;
    }

    // Deserializza la receipt
    let receipt: Receipt = match bincode::deserialize(&buffer) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Errore deserializzazione prova: {}", e);
            return;
        }
    };

    // Estrai info dal profilo
    let (rpc_url, contract_addr, key) = match profile {
        ChainProfile::Anvil(cfg) => (cfg.rpc_url.clone(), cfg.contract, cfg.signer_private_key.clone()),
        ChainProfile::Sepolia(cfg) => (cfg.rpc_url.clone(), cfg.contract, cfg.wallet_private_key.clone()),
    };

    if let Err(e) = run_onchain_verification(&receipt, contract_addr, &key, rpc_url, metrics) {
        eprintln!("Errore durante la verifica on-chain: {:?}", e);
    } else {
        println!("Verifica on-chain da file completata con successo.");
    }
}



fn run_onchain_verification(
    receipt: &Receipt,
    contract_address: Address,
    signer_key: &str,
    rpc_url: Url,
    metrics: bool,
) -> Result<()> {
    // Setup wallet e provider
    let signer = PrivateKeySigner::from_str(signer_key)
        .context("Chiave privata non valida")?;
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url);

    // Encode seal
    let seal = encode_seal(receipt).context("Encoding seal fallito")?;
    let journal = receipt.journal.bytes.clone();

    // Setup contratto
    let contract = IContract::new(contract_address, provider);
    
    // Runtime per esecuzione async
    let runtime = tokio::runtime::Runtime::new()?;

    // Setup metriche
    let mut tx_trace = if metrics {
        let f = File::options().append(true).create(true).open("tx_trace_metrics.csv")?;
        if f.metadata()?.len() == 0 {
            let mut f_ref = &f;
            writeln!(f_ref, "tx_hash,gas_used,gas_price,block_number,time_ms,success")?;
        }
        Some(f)
    } else {
        None
    };

    let mut verify_metrics_log = if metrics {
        let f = File::options().append(true).create(true).open("verify_metrics.csv")?;
        if f.metadata()?.len() == 0 {
            let mut f_ref = &f;
            writeln!(f_ref, "avg_gas_used,avg_gas_price,avg_time_ms,success_pct")?;
        }
        Some(f)
    } else {
        None
    };

    let mut times = Vec::new();
    let mut successes = 0;
    let mut gas_used = Vec::new();
    let mut gas_price = Vec::new();
    let total_runs = 10;

    println!("Avvio verifica on-chain ({} transazioni)...", total_runs);
    for i in 0..total_runs {
        // set(bytes journal, bytes seal)
        let call_builder = contract.set(journal.clone().into(), seal.clone().into());
        
        let t_start = Instant::now();
        
        // Invia transazione
        let pending_tx = runtime.block_on(call_builder.send())
            .context(format!("Errore invio transazione {}", i+1))?;
            
        // Attendi receipt
        let tx_receipt = runtime.block_on(pending_tx.get_receipt())
            .context(format!("Errore recupero receipt transazione {}", i+1))?;
            
        let duration_ms = t_start.elapsed().as_millis();
        let success = tx_receipt.status();
        
        if success { successes += 1; }
        
        let g_used = tx_receipt.gas_used;
        let g_price = tx_receipt.effective_gas_price;
        
        times.push(duration_ms);
        gas_used.push(g_used);
        gas_price.push(g_price);

        println!("Tx {}/{}: hash={:?}, success={}, gas={}, time={}ms", 
            i+1, total_runs, tx_receipt.transaction_hash, success, g_used, duration_ms);

        if let Some(ref mut f) = tx_trace {
            writeln!(f, "{:?},{},{},{},{},{}",
                tx_receipt.transaction_hash,
                g_used,
                g_price,
                tx_receipt.block_number.unwrap_or_default(),
                duration_ms,
                success
            )?;
        }
    }

    if let Some(ref mut f) = verify_metrics_log {
        let avg_gas = if !gas_used.is_empty() { gas_used.iter().map(|&x| x as u128).sum::<u128>() / gas_used.len() as u128 } else { 0 };
        let avg_price = if !gas_price.is_empty() { gas_price.iter().map(|&x| x as u128).sum::<u128>() / gas_price.len() as u128 } else { 0 };
        let avg_time = if !times.is_empty() { times.iter().map(|&x| x as u128).sum::<u128>() / times.len() as u128 } else { 0 };
        let success_rate = (successes as f64 / total_runs as f64) * 100.0;
        
        writeln!(f, "{},{},{},{:.2}", avg_gas, avg_price, avg_time, success_rate)?;
    }

    Ok(())
}

// Helper function for verification logic
fn verify_receipt_offchain(receipt: &Receipt, source_label: &str, metrics: bool) {
    println!("Avvio verifica off-chain (sorgente: {})...", source_label);
    let t_start = Instant::now();
    
    match receipt.verify(GUEST_ID) {
        Ok(()) => {
            let duration = t_start.elapsed().as_millis();
            println!("✅ Verifica off-chain completata con successo in {}ms", duration);
            
            if metrics {
                 if let Ok(mut f) = File::options().append(true).create(true).open("verify_offchain_metrics.csv") {
                    if f.metadata().map(|m| m.len() == 0).unwrap_or(false) {
                        let _ = writeln!(f, "source,success,time_ms");
                    }
                    let _ = writeln!(f, "{},true,{}", source_label, duration);
                }
            }
        },
        Err(e) => {
            let duration = t_start.elapsed().as_millis();
            eprintln!("❌ Verifica off-chain FALLITA: {:?}", e);
             if metrics {
                 if let Ok(mut f) = File::options().append(true).create(true).open("verify_offchain_metrics.csv") {
                    if f.metadata().map(|m| m.len() == 0).unwrap_or(false) {
                        let _ = writeln!(f, "source,success,time_ms");
                    }
                    let _ = writeln!(f, "{},false,{}", source_label, duration);
                }
            }
        }
    }
}

// verifica offchain con file
fn exec_verify_offchain_from_file_stub(path: &str, metrics: bool) {
    println!("Caricamento prova da file: {}", path);
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Errore apertura file prova: {}", e);
            return;
        }
    };
    let mut buffer = Vec::new();
    if let Err(e) = file.read_to_end(&mut buffer) {
        eprintln!("Errore lettura file prova: {}", e);
        return;
    }

    let receipt: Receipt = match bincode::deserialize(&buffer) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Errore deserializzazione prova: {}", e);
            return;
        }
    };

    verify_receipt_offchain(&receipt, "file", metrics);
}

// verifica offchain con prova generata in questa sessione
fn exec_verify_offchain_from_new_stub(receipts: &[(Backend, Receipt)], metrics: bool) {
    if receipts.is_empty() {
        println!("⚠️ Nessuna prova disponibile per la verifica off-chain.");
        return;
    }
    for (backend, receipt) in receipts {
        let backend_name = match backend { Backend::Stark => "stark", Backend::Groth16 => "groth16" };
        verify_receipt_offchain(receipt, backend_name, metrics);
    }
}

// verifica onchain con prova generata in questa sessione
fn exec_verify_onchain_from_new_stub(
    receipt: Option<&Receipt>,
    profile: &ChainProfile,
    metrics: bool
) {
    let (rpc_url, contract_addr, key) = match profile {
        ChainProfile::Anvil(cfg) => (cfg.rpc_url.clone(), cfg.contract, cfg.signer_private_key.clone()),
        ChainProfile::Sepolia(cfg) => (cfg.rpc_url.clone(), cfg.contract, cfg.wallet_private_key.clone()),
    };

    if let Some(r) = receipt {
        println!("Avvio verifica on-chain (Groth16)...");
        if let Err(e) = run_onchain_verification(r, contract_addr, &key, rpc_url, metrics) {
            eprintln!("❌ Errore durante la verifica on-chain: {:?}", e);
        } else {
            println!("✅ Verifica on-chain completata con successo.");
        }
    } else {
        eprintln!("⚠️  Nessuna prova Groth16 disponibile per la verifica on-chain.");
    }
}


//TODO MAIN FUN
fn main() -> Result<()> {

    // Acquisizione dei paramentri da riga di comando 
    let cli = Cli::parse();
    match cli.command {
        Commands::Run(RunCmd { input, session, prove, verify, network, source, proof_file, wallet, metrics }) => {
            // Validazioni incrociate delle combinazioni richieste
            validate_run(&RunCmd {
                input: input.clone(),
                session,
                prove: prove.clone(),
                verify,
                network,
                source,
                proof_file: proof_file.clone(),
                wallet: wallet.clone(),
                metrics,
            })?;

            // DEBUG: stampa dei parametri acquisiti da riga di comando
            println!("Informazioni rilevate:");
            println!("Input: {:?}", input);
            println!("Sessione: {}", session);
            let provers: Vec<&'static str> = prove
                .iter()
                .map(|backend| match backend { Backend::Stark => "stark", Backend::Groth16 => "groth16" })
                .collect();
            println!("Prove backends: {:?}", provers);
            println!("Verifica: {:?}", verify);
            println!("Network: {:?}", network);
            println!("Source: {:?}", source);
            println!("Proof file: {:?}", proof_file);
            println!("Wallet: {}", if wallet.is_some() { "[acquisito]" } else { "-" });
            println!("Metriche: {}", metrics);

            // Parsing e validazione dell'input (se presente)
            let typed_input_opt: Option<TypedInput> = match &input {
                Some(spec) => Some(parse_typed_input(spec).map_err(|e| anyhow::anyhow!("Errore input: {}", e))?),
                None => None,
            };

            // Dispatcher stub (session, proving, verify)

            // ABI encoding unico se serve (session o prove o source=new)
            let encoded_input_opt: Option<Vec<u8>> = typed_input_opt.as_ref().map(|ti| match &ti.validated {
                ValidatedSolData::Uint256(n) => n.abi_encode(),
                ValidatedSolData::Uint256Triple(b,e,m) => (b.clone(),e.clone(),m.clone()).abi_encode(),
                ValidatedSolData::String(s) => s.clone().abi_encode(),
                ValidatedSolData::Bytes(b) => Bytes::from(b.clone()).abi_encode(),
                ValidatedSolData::Bool(v) => v.abi_encode(),
                ValidatedSolData::Address(a) => a.abi_encode(),
                ValidatedSolData::BytesN(arr,_) => Bytes::from(arr.clone()).abi_encode(),
            });

            // generazione di una session
            if session {
                if let (Some(encoded_input), Some(_ti)) = (&encoded_input_opt, &typed_input_opt) {
                    let original_spec = input.as_deref().unwrap_or("");
                    let _session = exec_session_stub(encoded_input, original_spec, metrics)?;
                }
            }

            // generazione prove (sostituisce stub)
            let mut generated_receipts: Vec<(Backend, Receipt)> = Vec::new();
            let mut groth16_receipt: Option<Receipt> = None;
            if !prove.is_empty() {
                if let (Some(encoded_input), Some(_ti)) = (&encoded_input_opt, &typed_input_opt) {
                    for backend in &prove {
                       let receipt = generate_proof_for_backend(*backend, encoded_input, metrics)?;
                        if *backend == Backend::Groth16 {   
                            groth16_receipt = Some(receipt.clone());
                        }
                        generated_receipts.push((*backend, receipt));
                    }
                }
            }
            
            // verifica di una prova
            if let Some(vmode) = verify {
                match (source, vmode) {
                    // import della prova da locale
                    // offchain
                    (Some(VerifySource::File), VerifyMode::Offchain) => {
                        if let Some(path) = &proof_file { exec_verify_offchain_from_file_stub(path, metrics); }
                    }
                    // onchain
                    (Some(VerifySource::File), VerifyMode::Onchain) => {
                        if let Some(path) = &proof_file {
                            let profile = build_chain_profile(&RunCmd { input: input.clone(), session, prove: prove.clone(), verify, network, source, proof_file: proof_file.clone(), wallet: wallet.clone(), metrics })?
                                .expect("Profilo onchain assente");
//TODO
                            exec_verify_onchain_from_file(path, &profile, metrics);
                        }
                    }
                    // prova generata nell'attuale esecuzione
                    // offchain 
                    (Some(VerifySource::New), VerifyMode::Offchain) => {
                        // Verifica locale tutte le prove appena generate (tutti i backend richiesti)
                        exec_verify_offchain_from_new_stub(&generated_receipts, metrics);
                    }
                    // onchain (only groth16)
                    (Some(VerifySource::New), VerifyMode::Onchain) => {
                        // On-chain: verifica solo prove Groth16
                        let profile = build_chain_profile(&RunCmd { input: input.clone(), session, prove: prove.clone(), verify, network, source, proof_file: proof_file.clone(), wallet: wallet.clone(), metrics })?
                            .expect("Profilo onchain assente");
                        exec_verify_onchain_from_new_stub(groth16_receipt.as_ref(), &profile, metrics);
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

