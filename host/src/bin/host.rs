// Copyright 2024 RISC Zero, Inc. and Risc0Flow Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! # Risc0Flow Host Application
//!
//! This module implements the host-side orchestrator for the RISC Zero zkVM proving pipeline.
//! It provides a non-interactive CLI to manage the complete lifecycle of zero-knowledge proofs:
//!
//! 1. **Session Execution**: Run the guest program in the zkVM executor to generate a trace.
//! 2. **Proof Generation**: Generate cryptographic proofs (STARK or Groth16) from the execution trace.
//! 3. **Verification**: Verify proofs either off-chain (locally) or on-chain (Ethereum).
//!
//! ## Architecture Overview
//!
//! ## Supported Data Types
//!
//! The host supports Solidity-compatible ABI encoding for the following types:
//! - `uint256`, `uint<M>` (where M is 8-256, multiple of 8)
//! - `string`, `bytes`, `bytes<N>` (where N is 1-32)
//! - `bool`, `address`
//! - `merkle_proof` (custom type for Merkle tree membership proofs)

// ============================================================================
// EXTERNAL DEPENDENCIES
// ============================================================================

// Alloy: A comprehensive Ethereum toolkit providing types, RPC client, and transaction signing.
// Used for all blockchain interactions including wallet management and contract calls.
use alloy::{
    network::EthereumWallet, providers::ProviderBuilder, signers::local::PrivateKeySigner,
    sol_types::SolValue,
};
use alloy_primitives::{Address, Bytes, FixedBytes};
use alloy_primitives::U256;

// Anyhow: Ergonomic error handling with context propagation.
// Provides the `Result` type alias and `Context` trait for adding error context.
use anyhow::{Context, Result};

// Methods crate: Auto-generated at build time, contains the compiled guest ELF binary
// and its cryptographic image ID (a commitment to the guest code).
use methods::{GUEST_ELF, GUEST_ID};

// RISC Zero Ethereum Contracts: Utilities for packaging proofs for on-chain verification.
// `encode_seal` converts a Receipt into the format expected by the Solidity verifier.
use risc0_ethereum_contracts::encode_seal;

// RISC Zero zkVM: Core proving infrastructure.
// - `default_prover`: Factory for the configured prover backend (local or Bonsai).
// - `ExecutorEnv`: Environment for guest execution, including input data.
// - `ExecutorImpl`: The zkVM executor that runs guest code and produces execution traces.
// - `ProverOpts`: Configuration for proof generation (STARK, Groth16, etc.).
// - `VerifierContext`: Context for proof verification.
// - `Receipt`: The cryptographic proof artifact containing seal and journal.
// - `Session`: Execution trace from running the guest, used for proving.
use risc0_zkvm::{
    default_prover, ExecutorEnv, ExecutorImpl, ProverOpts, VerifierContext, Receipt, Session,
};

// Alloy sol! macro: Generates Rust bindings from Solidity interface files.
// This creates type-safe contract interaction code from IContract.sol.
alloy::sol!(
    #[sol(rpc, all_derives)]
    "../contracts/IContract.sol"
);

// URL parsing for RPC endpoints.
use url::Url;

// Standard library imports for file I/O, timing, and string operations.
use std::{
    fs::File,
    io::{Read, Write},
    time::Instant,
    error::Error,
    fmt,
    str::FromStr,
};

// Date/time formatting for human-readable timestamps in filenames.
use chrono::Local;

// SHA-256 hashing for generating input identifiers.
use sha2::{Sha256, Digest};

// System metrics module for monitoring CPU and memory usage during proof generation.
mod system_metrics;
use system_metrics::MetricsMonitor;


// ============================================================================
// TYPE VALIDATION SYSTEM
// ============================================================================
//
// This section implements a type-safe parsing and validation layer for Solidity
// data types. It ensures that user input conforms to the expected format before
// ABI encoding and transmission to the guest program.

/// Represents errors that can occur during input parsing and validation.
/// 
/// This enum provides specific error variants to help users diagnose input issues:
/// - `UnknownType`: The declared type is not in the set of supported Solidity types.
/// - `InvalidDataFormat`: The data does not conform to the declared type's format.
#[derive(Debug, PartialEq)]
pub enum ParseError {
    /// The declared type identifier is not recognized by the parser.
    /// Contains the unrecognized type string for error reporting.
    UnknownType(String),
    
    /// The data value does not conform to the expected format for its declared type.
    /// Contains a descriptive error message explaining the format violation.
    InvalidDataFormat(String),
}

/// Represents a successfully parsed and validated Solidity data value.
/// 
/// Each variant corresponds to a Solidity type and contains the parsed Rust
/// representation ready for ABI encoding. This enum serves as the intermediate
/// representation between raw user input and ABI-encoded bytes.
#[derive(Debug, PartialEq, Clone)]
pub enum ValidatedSolData {
    /// A 256-bit unsigned integer. Corresponds to Solidity's `uint256`.
    Uint256(U256),
    
    /// A tuple of three 256-bit unsigned integers.
    /// Used for operations requiring multiple numeric inputs (e.g., modular exponentiation).
    Uint256Triple(U256, U256, U256),
    
    /// A UTF-8 encoded string. Corresponds to Solidity's `string` type.
    String(String),
    
    /// A dynamic byte array. Corresponds to Solidity's `bytes` type.
    Bytes(Vec<u8>),
    
    /// A boolean value. Corresponds to Solidity's `bool` type.
    Bool(bool),
    
    /// An Ethereum address (20 bytes). Corresponds to Solidity's `address` type.
    Address(Address),
    
    /// A fixed-size byte array. Corresponds to Solidity's `bytes1` through `bytes32`.
    /// The tuple contains (value, N) where N is the byte length (1 <= N <= 32).
    BytesN(Vec<u8>, usize),
    
    /// Merkle tree proof of membership.
    /// 
    /// This type encapsulates all data required to verify that a leaf belongs to
    /// a Merkle tree with a known root. The guest program will recompute the root
    /// from the leaf and proof path, then assert equality with the expected root.
    /// 
    /// # Fields
    /// - leaf: The SHA-256 hash of the leaf node (pre-hashed by the caller).
    /// - siblings: Array of sibling hashes along the path from leaf to root.
    /// - directions: Boolean array indicating sibling positions.
    ///   - true: Sibling is on the right; concatenate as hash(current || sibling).
    ///   - false: Sibling is on the left; concatenate as hash(sibling || current).
    /// - expected_root: The known root hash that the proof should reconstruct.
    MerkleProof {
        leaf: [u8; 32],
        siblings: Vec<[u8; 32]>,
        directions: Vec<bool>,
        expected_root: [u8; 32],
    },
}

/// Represents a fully parsed and validated typed input.
/// 
/// This structure is the result of successfully parsing user input in the format
/// `<type; data>`. It preserves both the original string representations (for
/// logging and error reporting) and the validated data (for ABI encoding).
/// 
/// # Fields
/// - `type_name`: The original type declaration string (e.g., "uint256", "merkle_proof").
/// - `data`: The original data string as provided by the user.
/// - `validated`: The parsed and validated data, ready for ABI encoding.
#[derive(Debug, Clone)]
#[allow(dead_code)]
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

// Represents the supported proving backends available via CLI
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Backend {
    #[value(name = "stark")] Stark,
    #[value(name = "groth16")] Groth16,
}

// Specifies the origin of the proof to verify: generated in this session or imported from file
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum VerifySource { #[value(name = "new")] New, #[value(name = "file")] File }

// Specifies the verification mode: offchain (local) or onchain (Ethereum)
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum VerifyMode { #[value(name = "offchain")] Offchain, #[value(name = "onchain")] Onchain }

// Specifies which network to use for on-chain verification: Anvil (local) or Sepolia (testnet)
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Network { #[value(name = "anvil")] Anvil, #[value(name = "sepolia")] Sepolia }


// ============================================================================
// BLOCKCHAIN NETWORK CONFIGURATION
// ============================================================================
//
// These structures encapsulate all network-specific parameters required for
// on-chain verification. They are constructed from CLI arguments and environment
// variables, providing a clean abstraction over network differences.

/// Configuration for the Anvil local development network.
/// 
/// Anvil is Foundry's local Ethereum node, designed for development and testing.
/// It uses deterministic accounts derived from a known mnemonic, eliminating
/// the need for real funds or external key management.
/// 
/// # Default Values
/// - Chain ID: 31337 (Anvil's standard chain ID)
/// - RPC URL: http://localhost:8545
/// - Signer: Account 0 from Anvil's default mnemonic
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct AnvilConfig {
    chain_id: u64,
    rpc_url: Url,
    contract: Address,
    signer_private_key: String,
}

/// Configuration for the Sepolia testnet.
/// 
/// Sepolia is Ethereum's recommended testnet for application testing.
/// It requires testnet ETH (obtainable from faucets) and a real wallet.
/// 
/// # Security Note
/// The wallet private key should be provided via the `--wallet` CLI argument.
/// Never use a mainnet private key on testnets.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SepoliaConfig {
    chain_id: u64,
    rpc_url: Url,
    contract: Address,
    wallet_private_key: String,
}

/// Unified chain profile enumeration.
/// 
/// This enum allows functions to accept either network configuration
/// polymorphically, extracting the relevant parameters as needed.
#[derive(Debug, Clone)]
enum ChainProfile {
    Anvil(AnvilConfig),
    Sepolia(SepoliaConfig),
}

use std::path::Path;

// CLI definition and argument parsing

// Main CLI struct definition
#[derive(Parser, Debug)]
#[command(
    name = "host",
    about = "Non-interactive CLI for orchestrating session, proving, and verification",
    version,
    long_about = "Single command: run. Input format: <type_1, ..., type_n; val_1, ..., val_n>.\n\
    Backends: stark, groth16. Verification: first choose source (new | file), then mode (offchain | onchain).\n\
    For onchain, specify network: anvil | sepolia (sepolia requires --wallet).",
    help_template = "{name} {version}\n\n{about}\n\nUSAGE:\n    {usage}\n\nCOMMANDS:\n{subcommands}\nGLOBAL OPTIONS:\n{options}\n\nEXAMPLES:\n  # Session\n  host run --input '<u256; 0x01>' --session\n  # Prove with 2 backends + metrics\n  host run --input '<u256; 0x01>' --prove stark groth16 --metrics\n  # Local offchain verification from file\n  host run --source file --proof-file proofs/proof.bin --verify offchain\n  # On-chain verification on Anvil from file\n  host run --source file --proof-file proofs/proof.bin --verify onchain --network anvil\n  # On-chain verification on Sepolia with freshly generated proof\n  host run --input '<u256; 0x02>' --prove groth16 --source new --verify onchain --network sepolia --wallet 0xYOUR_PRIVATE_KEY\n\nTips:\n  - First choose proof source: --source new (with --input and --prove) or --source file (with --proof-file)\n  - Then choose mode: --verify offchain | onchain; if onchain, also specify --network anvil|sepolia\n  - --wallet is required only with --verify onchain --network sepolia\n",
    subcommand_required = true,
    arg_required_else_help = true
)]

// Struct that encapsulates the set of available subcommands
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

// Run(RunCmd) defines the run subcommand: groups all pipeline flags
#[derive(Subcommand, Debug)]
enum Commands {
    #[command(
        about = "Executes the configured pipeline (session, proving, verification) in a single command",
        long_about = "Combines desired operations into a single execution: --session, --prove, --verify.",
        after_help = "Examples:\n  host run --input '<u256; 0x01>' --session\n  host run --input '<u256; 0x01>' --prove stark groth16\n  host run --verify offchain --source file --proof-file proofs/proof.bin\n  host run --source file --proof-file proofs/proof.bin --verify onchain --network anvil\n  host run --input '<u256; 0x02>' --prove groth16 --source new --verify onchain --network sepolia --wallet 0xYOUR_PRIVATE_KEY"
    )]
    Run(RunCmd),
}

// Collects all flags and options needed to describe
// a composite pipeline (session, proving, verification).
#[derive(Args, Debug)]
struct RunCmd {
    /// Input string: <type_1, ..., type_n; val_1, ..., val_n>
    #[arg(long, value_name = "INPUT_SPEC", conflicts_with = "input_file")]
    input: Option<String>,

    /// Path to file containing input string (alternative to --input for large inputs)
    #[arg(long, value_name = "INPUT_FILE", conflicts_with = "input")]
    input_file: Option<String>,

    /// Generate a session
    #[arg(long, default_value_t = false)]
    session: bool,

    /// Select proof backend(s) (one or more): stark, groth16
    #[arg(long, value_enum, num_args = 1.., value_name = "BACKEND")]
    prove: Vec<Backend>,

    /// Verification mode: offchain (local) | onchain
    #[arg(long, value_enum, value_name = "MODE")]
    verify: Option<VerifyMode>,

    /// On-chain network: anvil | sepolia (required if --verify onchain)
    #[arg(long, value_enum, value_name = "NETWORK")]
    network: Option<Network>,

    /// Proof source: new | file
    #[arg(long, value_enum, value_name = "SOURCE")]
    source: Option<VerifySource>,

    /// Proof file path (required if --source file)
    #[arg(long, value_name = "FILE")]
    proof_file: Option<String>,

    /// Wallet private key (required if --verify onchain --network sepolia)
    #[arg(long, value_name = "WALLET")]
    wallet: Option<String>,

    /// Number of verification transactions to execute (default: 1)
    #[arg(long, default_value_t = 1)]
    n_runs: usize,

    /// Enable metrics collection
    #[arg(long, default_value_t = false)]
    metrics: bool,
}


// ============================================================================
// INPUT VALIDATION AND PARSING
// ============================================================================

/// Validates the combination of CLI flags for the `run` subcommand.
/// 
/// This function enforces the logical constraints between different options,
/// preventing ambiguous or incomplete configurations before execution begins.
/// 
/// # Validation Rules
/// 
/// 1. **Operation Selection**: At least one of `--session`, `--prove`, or `--verify` must be specified.
/// 2. **Verification Dependencies**:
///    - `--verify` requires `--source` (new or file).
///    - `--verify onchain` requires `--network` (anvil or sepolia).
/// 3. **Source Dependencies**:
///    - `--source new` requires `--prove` and `--input`.
///    - `--source file` requires `--proof-file`.
/// 4. **On-chain Requirements**:
///    - On-chain verification requires a Groth16 proof.
///    - Sepolia network requires `--wallet`.
/// 5. **Mutual Exclusions**:
///    - `--source new` is incompatible with `--proof-file`.
///    - `--source file` is incompatible with `--input`.
///    - `--wallet` is only valid for Sepolia on-chain verification.
/// 
/// # Returns
/// - `Ok(())` if all validations pass.
/// - `Err` with a descriptive message if any validation fails.
fn validate_run(cmd: &RunCmd) -> Result<()> {
    use anyhow::{bail, ensure};

    // At least one operation must be selected
    let any_op = cmd.session || !cmd.prove.is_empty() || cmd.verify.is_some();
    ensure!(any_op, "No operation selected: use at least one of --session, --prove, --verify");

    // --verify requires --source
    if cmd.verify.is_some() && cmd.source.is_none() {
        bail!("--verify requires --source (new|file)");
    }

    // --verify onchain requires --network
    if matches!(cmd.verify, Some(VerifyMode::Onchain)) && cmd.network.is_none() {
        bail!("--verify onchain requires --network (anvil|sepolia)");
    }

    // --network not allowed if verify=offchain or absent
    if (matches!(cmd.verify, Some(VerifyMode::Offchain)) || cmd.verify.is_none()) && cmd.network.is_some() {
        bail!("--network is only valid with --verify onchain");
    }

    // --verify with --source new requires at least one proof backend in the same command
    if matches!(cmd.source, Some(VerifySource::New)) && cmd.verify.is_some() && cmd.prove.is_empty() {
        bail!("Verification with --source new also requires --prove <BACKEND>... (no proof requested)");
    }

    // On-chain requires groth16 backend (only proof verifiable on-chain)
    if matches!(cmd.verify, Some(VerifyMode::Onchain))
        && matches!(cmd.source, Some(VerifySource::New))
        && !cmd.prove.iter().any(|b| matches!(b, Backend::Groth16))
    {
        bail!("--verify onchain requires at least one groth16 proof when --source new");
    }

    // --input required for session/prove/source=new
    let needs_input = cmd.session || !cmd.prove.is_empty() || matches!(cmd.source, Some(VerifySource::New));
    if needs_input {
        let has_input = cmd.input.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false);
        ensure!(has_input, "--input is required for --session, --prove, or --source new");
    }

    // --proof-file required for source=file
    if matches!(cmd.source, Some(VerifySource::File)) {
        let has_file = cmd.proof_file.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false);
        ensure!(has_file, "--proof-file is required when --source file");
    }

    // --wallet required for onchain sepolia
    if matches!(cmd.verify, Some(VerifyMode::Onchain)) && matches!(cmd.network, Some(Network::Sepolia)) {
        let has_wallet = cmd.wallet.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false);
        ensure!(has_wallet, "--wallet is required when --verify onchain --network sepolia");
    }

    // Additional constraints to avoid redundant/ambiguous combinations
    // 1) With source=new, --proof-file should not be passed
    if matches!(cmd.source, Some(VerifySource::New)) && cmd.proof_file.is_some() {
        bail!("With --source new, do not use --proof-file (only valid for --source file)");
    }

    // 2) With source=file, --input should not be passed (not required, potentially ambiguous)
    if matches!(cmd.source, Some(VerifySource::File)) && cmd.input.is_some() {
        bail!("With --source file, do not use --input (only needed for --source new or prove/session)");
    }

    // 3) With verify=offchain, --wallet should not be passed
    if matches!(cmd.verify, Some(VerifyMode::Offchain)) && cmd.wallet.is_some() {
        bail!("--wallet is only valid with --verify onchain --network sepolia (not with offchain)");
    }

    // 4) With verify=onchain and network=anvil, --wallet should not be passed
    if matches!(cmd.verify, Some(VerifyMode::Onchain)) && matches!(cmd.network, Some(Network::Anvil)) && cmd.wallet.is_some() {
        bail!("--wallet is only valid with --verify onchain --network sepolia (not with anvil)");
    }

    Ok(())
}


// Implement standard error traits for ParseError to enable use with anyhow and other error handling.
impl Error for ParseError {}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseError::UnknownType(type_str) => {
                write!(f, "Unknown type: '{}'", type_str)
            }
            ParseError::InvalidDataFormat(err_msg) => {
                write!(f, "Invalid data format: {}", err_msg)
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
                .map_err(|e| ParseError::InvalidDataFormat(format!("invalid uint256: {}", e)))
        },

        // Triple is already handled above more permissively

        "string" => {
            if data.is_empty() {
                Err(ParseError::InvalidDataFormat("string cannot be empty".to_string()))
            } else {
                Ok(ValidatedSolData::String(data.to_string()))
            }
        },

        "bytes" => {
            if !data.starts_with("0x") {
                return Err(ParseError::InvalidDataFormat("bytes must start with 0x".to_string()));
            }
            hex::decode(&data[2..])
                .map(ValidatedSolData::Bytes)
                .map_err(|e| ParseError::InvalidDataFormat(format!("invalid bytes: {}", e)))
        },

        "bool" => {
            match data.to_lowercase().as_str() {
                "true" | "1" => Ok(ValidatedSolData::Bool(true)),
                "false" | "0" => Ok(ValidatedSolData::Bool(false)),
                _ => Err(ParseError::InvalidDataFormat("bool must be true/false/1/0".to_string()))
            }
        },

        _ => {
            // uint<M>
            if let Some(rest) = typedata.strip_prefix("uint") {
                if rest.is_empty() {
                    return Err(ParseError::InvalidDataFormat("uint without size: use uint256 or uint<M>".to_string()));
                }
                let bits: u16 = rest.parse().map_err(|_| ParseError::InvalidDataFormat("invalid uint size".to_string()))?;
                if bits % 8 != 0 || bits == 0 || bits > 256 {
                    return Err(ParseError::InvalidDataFormat("uint<M>: M must be a multiple of 8, 8..=256".to_string()));
                }
                let val = U256::from_str(data).map_err(|e| ParseError::InvalidDataFormat(format!("invalid uint{}: {}", bits, e)))?;
                if bits < 256 {
                    let bound = U256::from(1u64) << (bits as u32);
                    if val >= bound {
                        return Err(ParseError::InvalidDataFormat(format!("value out of range for uint{}", bits)));
                    }
                }
                // Note: for encoding we treat as uint256 (ABI word) on host side
                return Ok(ValidatedSolData::Uint256(val));
            }

            // bytesN (1..=32)
            if let Some(rest) = typedata.strip_prefix("bytes") {
                if !rest.is_empty() {
                    let n: usize = rest.parse().map_err(|_| ParseError::InvalidDataFormat("bytesN: invalid N".to_string()))?;
                    if n == 0 || n > 32 {
                        return Err(ParseError::InvalidDataFormat("bytesN: N must be 1..=32".to_string()));
                    }
                    if !data.starts_with("0x") { return Err(ParseError::InvalidDataFormat("bytesN must start with 0x".to_string())); }
                    let hex_part = &data[2..];
                    if hex_part.len() != n * 2 {
                        return Err(ParseError::InvalidDataFormat(format!("bytes{}: expected {} hex chars, found {}", n, n*2, hex_part.len())));
                    }
                    let v = hex::decode(hex_part).map_err(|e| ParseError::InvalidDataFormat(format!("invalid bytes{}: {}", n, e)))?;
                    return Ok(ValidatedSolData::BytesN(v, n));
                }
            }

            // address
            if typedata == "address" {
                let addr = Address::from_str(data).map_err(|_| ParseError::InvalidDataFormat("invalid address (expected 0x + 40 hex)".to_string()))?;
                return Ok(ValidatedSolData::Address(addr));
            }

            // merkle_proof: format <merkle_proof; leaf=0x..., siblings=[0x...,0x...], directions=[l,r,...], root=0x...>
            if typedata == "merkle_proof" {
                return parse_merkle_proof(data);
            }

            Err(ParseError::UnknownType(typedata.to_string()))
        },
    }
}


/// Specialized parser for the `merkle_proof` type.
/// 
/// Parses a Merkle proof specification string into its component parts and validates
/// consistency constraints. The proof data is used by the guest program to verify
/// membership in a Merkle tree.
/// 
/// # Input Format
/// 
/// ```text
/// leaf=0x<64 hex chars>, siblings=[0x<64>,...], directions=[l|r,...], root=0x<64 hex chars>
/// ```
/// 
/// ## Field Descriptions
/// 
/// - **leaf**: The SHA-256 hash of the data element to prove membership for.
/// - **siblings**: Array of sibling hashes along the path from leaf to root.
/// - **directions**: Position of each sibling relative to the current node:
///   - `l`, `left`, `0`, `false`: Sibling is on the left.
///   - `r`, `right`, `1`, `true`: Sibling is on the right.
/// - **root**: The expected Merkle root that the proof should reconstruct.
/// 
/// # Validation
/// 
/// - All hashes must be exactly 32 bytes (64 hex characters).
/// - `siblings` and `directions` arrays must have the same length.
/// - At least one sibling must be provided (tree depth >= 1).
/// 
/// # Example
/// 
/// ```text
/// leaf=0xabc123..., siblings=[0xdef456...], directions=[r], root=0x789abc...
/// ```
fn parse_merkle_proof(data: &str) -> Result<ValidatedSolData, ParseError> {
    // Helper to extract a value from a key
    fn extract_value<'a>(data: &'a str, key: &str) -> Option<&'a str> {
        // Search for "key=" in data
        let pattern = format!("{}=", key);
        if let Some(start_idx) = data.find(&pattern) {
            let value_start = start_idx + pattern.len();
            let remaining = &data[value_start..];
            
            // If starts with '[', find matching ']'
            if remaining.starts_with('[') {
                if let Some(end_idx) = remaining.find(']') {
                    return Some(&remaining[..=end_idx]);
                }
            } else {
                // Otherwise take until next comma or end of string
                let end_idx = remaining.find(',').unwrap_or(remaining.len());
                return Some(remaining[..end_idx].trim());
            }
        }
        None
    }

    // Helper to parse a bytes32 value
    fn parse_bytes32(hex_str: &str) -> Result<[u8; 32], ParseError> {
        let hex_str = hex_str.trim();
        if !hex_str.starts_with("0x") {
            return Err(ParseError::InvalidDataFormat(
                format!("bytes32 must start with 0x, found: '{}'", hex_str)
            ));
        }
        let hex_part = &hex_str[2..];
        if hex_part.len() != 64 {
            return Err(ParseError::InvalidDataFormat(
                format!("bytes32 requires 64 hex characters, found {}", hex_part.len())
            ));
        }
        let bytes = hex::decode(hex_part).map_err(|e| 
            ParseError::InvalidDataFormat(format!("invalid bytes32 hex: {}", e))
        )?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    // Helper to parse an array of bytes32
    fn parse_bytes32_array(arr_str: &str) -> Result<Vec<[u8; 32]>, ParseError> {
        let arr_str = arr_str.trim();
        if !arr_str.starts_with('[') || !arr_str.ends_with(']') {
            return Err(ParseError::InvalidDataFormat(
                "siblings array must be enclosed in [ and ]".to_string()
            ));
        }
        let inner = &arr_str[1..arr_str.len()-1];
        if inner.trim().is_empty() {
            return Ok(Vec::new());
        }
        
        let mut result = Vec::new();
        for item in inner.split(',') {
            let item = item.trim();
            if !item.is_empty() {
                result.push(parse_bytes32(item)?);
            }
        }
        Ok(result)
    }

    // Helper to parse a directions array
    fn parse_directions(arr_str: &str) -> Result<Vec<bool>, ParseError> {
        let arr_str = arr_str.trim();
        if !arr_str.starts_with('[') || !arr_str.ends_with(']') {
            return Err(ParseError::InvalidDataFormat(
                "directions array must be enclosed in [ and ]".to_string()
            ));
        }
        let inner = &arr_str[1..arr_str.len()-1];
        if inner.trim().is_empty() {
            return Ok(Vec::new());
        }
        
        let mut result = Vec::new();
        for item in inner.split(',') {
            let item = item.trim().to_lowercase();
            let dir = match item.as_str() {
                "r" | "right" | "1" | "true" => true,   // sibling on the right
                "l" | "left" | "0" | "false" => false,  // sibling on the left
                _ => return Err(ParseError::InvalidDataFormat(
                    format!("invalid direction: '{}'. Use l/left/0 or r/right/1", item)
                )),
            };
            result.push(dir);
        }
        Ok(result)
    }

    // Extract required fields
    let leaf_str = extract_value(data, "leaf")
        .ok_or_else(|| ParseError::InvalidDataFormat("missing 'leaf' field".to_string()))?;
    let siblings_str = extract_value(data, "siblings")
        .ok_or_else(|| ParseError::InvalidDataFormat("missing 'siblings' field".to_string()))?;
    let directions_str = extract_value(data, "directions")
        .ok_or_else(|| ParseError::InvalidDataFormat("missing 'directions' field".to_string()))?;
    let root_str = extract_value(data, "root")
        .ok_or_else(|| ParseError::InvalidDataFormat("missing 'root' field".to_string()))?;

    // Parse individual fields
    let leaf = parse_bytes32(leaf_str)?;
    let siblings = parse_bytes32_array(siblings_str)?;
    let directions = parse_directions(directions_str)?;
    let expected_root = parse_bytes32(root_str)?;

    // Consistency validations
    if siblings.len() != directions.len() {
        return Err(ParseError::InvalidDataFormat(
            format!("siblings ({}) and directions ({}) must have the same length", 
                siblings.len(), directions.len())
        ));
    }

    if siblings.is_empty() {
        return Err(ParseError::InvalidDataFormat(
            "Merkle proof must have at least one sibling (depth >= 1)".to_string()
        ));
    }

    Ok(ValidatedSolData::MerkleProof {
        leaf,
        siblings,
        directions,
        expected_root,
    })
}


fn parse_typed_input(spec: &str) -> Result<TypedInput, ParseError> {
    let trimmed = spec.trim();
    if !trimmed.starts_with('<') || !trimmed.ends_with('>') {
        return Err(ParseError::InvalidDataFormat("Input must be enclosed in < and >".into()));
    }
    let inner = &trimmed[1..trimmed.len()-1];
    let parts: Vec<&str> = inner.splitn(2, ';').collect();
    if parts.len() != 2 {
        return Err(ParseError::InvalidDataFormat("Format must be <type; data>".into()));
    }
    let type_name = parts[0].trim();
    let data = parts[1].trim();
    if type_name.is_empty() || data.is_empty() {
        return Err(ParseError::InvalidDataFormat("Type or data is empty".into()));
    }
    let validated = parse_and_validate_typed(type_name, data)?;
    Ok(TypedInput { type_name: type_name.to_string(), data: data.to_string(), validated })
}


// ============================================================================
// INPUT TRACKING UTILITIES
// ============================================================================

/// Computes an 8-character hex hash of the encoded input bytes.
/// 
/// This hash serves as a unique identifier for tracking inputs across
/// metrics files and proof outputs.
/// 
/// # Arguments
/// 
/// - `encoded_input`: The ABI-encoded input bytes.
/// 
/// # Returns
/// 
/// An 8-character hex string (first 4 bytes of SHA-256).
fn compute_input_hash(encoded_input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(encoded_input);
    let result = hasher.finalize();
    hex::encode(&result[..4])
}

/// Saves the human-readable input specification to a file for reference.
/// 
/// Creates a file `metrics/input_<hash>.txt` containing the original input
/// string as provided on the command line. This allows correlating metrics
/// CSV rows (which contain only the hash) with the actual input data.
/// 
/// If the file already exists, it is not overwritten (same input = same hash).
/// 
/// # Arguments
/// 
/// - `input_hash`: The 8-character hash identifier.
/// - `input_spec`: The original input string (e.g., "<merkle_proof; leaf=...>").
fn save_input_reference(input_hash: &str, input_spec: &str) {
    let _ = std::fs::create_dir_all("metrics");
    let filename = format!("metrics/input_{}.csv", input_hash);
    let path = std::path::Path::new(&filename);
    
    // Only write if file doesn't exist (same input = same hash = same content)
    if !path.exists() {
        println!("DEBUG: saving input_hash={}, input_spec='{}'", input_hash, input_spec);
        let content = format!("input_id,input_spec\n{},{}", input_hash, input_spec);
        let _ = std::fs::write(&filename, content);
    }
}


// ============================================================================
// SESSION GENERATION
// ============================================================================

/// Executes the guest program in the zkVM to generate an execution trace (Session).
/// 
/// This function runs the guest code with the provided ABI-encoded input, producing
/// a `Session` object that contains the complete execution trace. The session can
/// then be used to generate cryptographic proofs.
/// 
/// # Process
/// 
/// 1. Constructs an `ExecutorEnv` with the input data.
/// 2. Loads the guest ELF binary into the executor.
/// 3. Runs the guest to completion, capturing the execution trace.
/// 4. Optionally records performance metrics to a CSV file.
/// 
/// # Arguments
/// 
/// - `encoded_input`: ABI-encoded input bytes to pass to the guest.
/// - `input_label`: Human-readable label for the input (used in metrics logging).
/// - `metrics`: If true, records timing and cycle count to `metrics/session_metrics_<timestamp>.csv`.
/// 
/// # Returns
/// 
/// - `Ok(Session)`: The execution trace, ready for proof generation.
/// - `Err`: If guest execution fails (e.g., assertion failure, invalid input).
/// 
/// # Metrics Recorded
/// 
/// | Column | Description |
/// |--------|-------------|
/// | `input_spec` | The input label/specification |
/// | `time_ms` | Execution time in milliseconds |
/// | `user_cycles` | Number of zkVM cycles consumed |
pub fn exec_session_stub(encoded_input: &[u8], input_label: &str, metrics: bool) -> Result<Session> {
    
    println!("Generating session...");
    let env = ExecutorEnv::builder()
        .write_slice(encoded_input)
        .build()?;

    let t0_exec_session = Instant::now();
    let mut exec_once = ExecutorImpl::from_elf(env, GUEST_ELF)?;
    let session_once: Session = exec_once.run()?;
    let t_exec_session: u128 = t0_exec_session.elapsed().as_millis();
    let user_cycles_once: u64 = session_once.user_cycles;

    if metrics {
        std::fs::create_dir_all("metrics")?;
        
        // Compute input hash and save reference file
        let input_hash = compute_input_hash(encoded_input);
        println!("DEBUG: input_label = '{}'", input_label);
        save_input_reference(&input_hash, input_label);
        
        let timestamp = Local::now().format("%d_%m_%y_%H_%M").to_string();
        let filename = format!("metrics/session_metrics_{}.csv", timestamp);
        let mut exec_log = File::options()
            .append(true)
            .create(true)
            .open(&filename)?;
        if exec_log.metadata()?.len() == 0 {
            writeln!(exec_log, "input_id,time_ms,user_cycles")?;
        }
        writeln!(exec_log, "{},{},{}", input_hash, t_exec_session, user_cycles_once)?;
    }
    println!("Session generation completed successfully");

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


// ============================================================================
// PROOF GENERATION
// ============================================================================

/// Generates a cryptographic proof for the specified backend.
/// 
/// This function executes the complete proving pipeline: running the guest,
/// generating the proof according to the selected backend, and serializing
/// the resulting receipt to disk for later verification.
/// 
/// # Proof Backends
/// 
/// | Backend | Proof System | Use Case |
/// |---------|--------------|----------|
/// | STARK | Scalable Transparent ARgument of Knowledge | Off-chain verification, intermediate proofs |
/// | Groth16 | Pairing-based zkSNARK | On-chain verification (constant gas cost) |
/// 
/// # Process
/// 
/// 1. Configures prover options based on the selected backend.
/// 2. Constructs an execution environment with the input data.
/// 3. Invokes the prover to generate the proof.
/// 4. Serializes the receipt to `proofs/receipt_<backend>_<timestamp>.bin`.
/// 5. Optionally records detailed metrics to CSV.
/// 
/// # Arguments
/// 
/// - `backend`: The proof system to use (STARK or Groth16).
/// - `encoded_input`: ABI-encoded input bytes for the guest.
/// - `metrics`: If true, records performance metrics.
/// 
/// # Returns
/// 
/// - `Ok(Receipt)`: The cryptographic proof artifact.
/// - `Err`: If proof generation fails.
/// 
/// # Metrics Recorded
/// 
/// | Column | Description |
/// |--------|-------------|
/// | `input_id` | 8-char hash of the input (reference to input file) |
/// | `backend` | STARK or Groth16 |
/// | `time_ms` | Total proving time |
/// | `seal_size` | Size of the cryptographic seal in bytes |
/// | `journal_len` | Size of the public journal in bytes |
/// | `peak_ram_kb` | Peak memory usage during proving |
/// | `avg_cpu_pct` | Average CPU utilization |
fn generate_proof_for_backend(
    backend: Backend,
    encoded_input: &[u8],
    input_label: &str,
    metrics: bool,
) -> Result<Receipt> {
    use anyhow::Context;

    // Determine backend name for logging and metrics
    let backend_name: &str = match backend { Backend::Stark => "stark", Backend::Groth16 => "groth16" };

    let is_dev_mode = std::env::var("RISC0_DEV_MODE").unwrap_or_default() == "1";

    // Configure prover options based on the selected backend
    let prover_opts = if is_dev_mode {
        println!("DEV MODE ACTIVE: Generating mock proof (not verifiable on-chain)");
        ProverOpts::default() 
    } else {
        match backend {
            Backend::Stark => ProverOpts::succinct(),
            Backend::Groth16 => ProverOpts::groth16(),
        }
    };

    // Construct a new execution environment for the proving phase
    let env = ExecutorEnv::builder()
        .write_slice(encoded_input)
        .build()
        .context("Failed to construct ExecutorEnv for proving")?;

    let t0 = Instant::now();
    
    // Start resource monitoring if metrics are enabled
    let monitor = if metrics { Some(MetricsMonitor::start()) } else { None };

    let prove_result = default_prover()
        .prove_with_ctx(env, &VerifierContext::default(), GUEST_ELF, &prover_opts)
        .context("Error during proof generation")?;
    
    // Stop monitoring and collect data
    let sys_metrics = if let Some(m) = monitor {
        Some(m.stop())
    } else {
        None
    };

    let elapsed_ms = t0.elapsed().as_millis();

    let receipt = prove_result.receipt;

    // SAVE PROOF TO FILE (for later verification from file)
    let receipt_bytes = bincode::serialize(&receipt).context("Receipt serialization failed")?;
    
    // Create proofs directory if it doesn't exist
    std::fs::create_dir_all("proofs").context("Failed to create proofs directory")?;

    // Generate human-readable timestamp (day_month_year_hour_minute)
    let timestamp = Local::now().format("%d_%m_%y_%H_%M").to_string();
    
    // Include input hash in filename for traceability
    let input_hash = compute_input_hash(encoded_input);

    let filename = format!("proofs/receipt_{}_{}_{}.bin", backend_name, input_hash, timestamp);
    std::fs::write(&filename, &receipt_bytes).context(format!("Failed to save {}", filename))?;
    println!("Proof saved to '{}'", filename);

    if metrics {
        std::fs::create_dir_all("metrics")?;
        
        // Compute input hash and save reference file
        let input_hash = compute_input_hash(encoded_input);
        save_input_reference(&input_hash, input_label);
        
        // CSV proving_metrics.csv: input_id,backend,phase,time_ms,seal_size,journal_len,receipt_bincode_len,peak_ram_kb,avg_cpu_pct,max_cpu_pct,max_threads
        let timestamp_metrics = Local::now().format("%d_%m_%y_%H_%M").to_string();
        let filename_metrics = format!("metrics/proving_metrics_{}.csv", timestamp_metrics);
        let mut file = File::options().append(true).create(true).open(&filename_metrics)?;
        if file.metadata()?.len() == 0 {
            writeln!(file, "input_id,backend,phase,time_ms,seal_size,journal_len,receipt_bincode_len,peak_ram_kb,avg_cpu_pct,max_cpu_pct,max_threads")?;
        }
        let seal_size = receipt.seal_size();
        let journal_len = receipt.journal.bytes.len();
        let receipt_ser_len = bincode::serialize(&receipt).map(|v| v.len()).unwrap_or(0);
        
        let (ram, avg_cpu, max_cpu, max_threads) = if let Some(sm) = sys_metrics {
            (sm.peak_ram_kb, sm.avg_cpu_usage, sm.max_cpu_usage, sm.max_threads)
        } else {
            (0, 0.0, 0.0, 0)
        };

        writeln!(
            file,
            "{},{},{},{},{},{},{},{},{:.2},{:.2},{}",
            input_hash,
            backend_name,
            "prove",
            elapsed_ms,
            seal_size,
            journal_len,
            receipt_ser_len,
            ram,
            avg_cpu,
            max_cpu,
            max_threads
        )?;
    }

    let receipt_total_size = bincode::serialize(&receipt).map(|v| v.len()).unwrap_or(0);
    let elapsed_secs = elapsed_ms / 1000;
    let elapsed_min = elapsed_secs / 60;
    let elapsed_sec = elapsed_secs % 60;
    println!("Proof generated: backend={}, time={}m{}s, seal_bytes={}, journal_bytes={}, receipt_bytes={}", 
             backend_name, elapsed_min, elapsed_sec, receipt.seal_size(), receipt.journal.bytes.len(), receipt_total_size);
    Ok(receipt)
}



// ============================================================================
// VERIFICATION PROCEDURES
// ============================================================================
//
// This section contains functions for both off-chain and on-chain proof verification.
// Off-chain verification uses the local RISC Zero verifier, while on-chain verification
// submits transactions to an Ethereum smart contract.

/// Attempts to automatically discover the deployed contract address for Anvil.
/// 
/// This function searches Foundry's broadcast directory for the most recent deployment
/// of the "Contract" contract on chain ID 31337 (Anvil's default). This enables
/// automatic contract discovery without manual address configuration.
/// 
/// # Search Paths
/// 
/// - `broadcast/Deploy.s.sol/31337/run-latest.json`
/// - `../broadcast/Deploy.s.sol/31337/run-latest.json`
/// 
/// # Returns
/// 
/// - `Some(Address)`: The contract address if found.
/// - `None`: If no deployment record is found.
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
                                            println!("Contract address extracted: {}", addr);
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

/// Attempts to automatically discover the deployed contract address for Sepolia.
/// 
/// Similar to `find_anvil_contract_address`, but searches for deployments on
/// chain ID 11155111 (Sepolia testnet).
/// 
/// # Search Paths
/// 
/// - `broadcast/Deploy.s.sol/11155111/run-latest.json`
/// - `../broadcast/Deploy.s.sol/11155111/run-latest.json`
/// 
/// # Returns
/// 
/// - `Some(Address)`: The contract address if found.
/// - `None`: If no deployment record is found.
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
                                            println!("Sepolia contract address extracted from broadcast: {}", addr);
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


/// Constructs a blockchain profile from CLI arguments and environment variables.
/// 
/// This function aggregates all network-specific configuration (chain ID, RPC URL,
/// contract address, signer key) into a unified `ChainProfile`. It supports both
/// Anvil (local) and Sepolia (testnet) networks.
/// 
/// # Configuration Sources
/// 
/// | Parameter | Anvil Source | Sepolia Source |
/// |-----------|--------------|----------------|
/// | Chain ID | Hardcoded (31337) | Hardcoded (11155111) |
/// | RPC URL | Hardcoded (localhost:8545) | `SEPOLIA_RPC_URL` env or default |
/// | Contract | Broadcast file or `CONTRACT_ADDRESS` env | Broadcast file, `SEPOLIA_CONTRACT_ADDRESS` env, or fallback |
/// | Signer | Anvil Account 0 (deterministic) | `--wallet` CLI argument |
/// 
/// # Returns
/// 
/// - `Ok(Some(ChainProfile))`: Profile for on-chain verification.
/// - `Ok(None)`: If verification mode is not on-chain.
/// - `Err`: If required configuration is missing.
fn build_chain_profile(cmd: &RunCmd) -> Result<Option<ChainProfile>> {
    
    if !matches!(cmd.verify, Some(VerifyMode::Onchain)) {
        return Ok(None);
    }

    let network = match cmd.network {
        Some(n) => n,
        None => return Ok(None), // already validated
    };

    match network {
        Network::Anvil => {
            // Use conventional defaults for Anvil local development network
            let chain_id = 31337u64;
            let rpc_url = Url::parse("http://localhost:8545").context("Invalid default Anvil RPC URL")?;
            
            // Attempt to automatically retrieve the contract address from Foundry's broadcast file
            let contract = find_anvil_contract_address()
                .or_else(|| std::env::var("CONTRACT_ADDRESS").ok().and_then(|s| Address::from_str(&s).ok()))
                .context("Contract address not found! Ensure you have deployed (broadcast/Deploy.s.sol/31337/run-latest.json) or set CONTRACT_ADDRESS.")?;

            println!("Contract automatically detected: {}", contract);

            // Private key: for Anvil, always use the default key (Account 0)
            // This key is deterministic for Anvil's default mnemonic
            let signer_private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string();
            Ok(Some(ChainProfile::Anvil(AnvilConfig { chain_id, rpc_url, contract, signer_private_key })))
        }
        Network::Sepolia => {
            let chain_id = 11155111u64;
            
            // Attempt to retrieve RPC URL from env, otherwise use default
            let rpc_url_str = std::env::var("SEPOLIA_RPC_URL")
                .unwrap_or_else(|_| "https://eth-sepolia.g.alchemy.com/v2/OKLxGgiSdmgSIz9G5FuKx".to_string());
            let rpc_url = Url::parse(&rpc_url_str).context("Invalid Sepolia RPC URL")?;

            // Attempt to retrieve address from env or broadcast, fallback to hardcoded
            let contract = std::env::var("SEPOLIA_CONTRACT_ADDRESS")
                .ok()
                .and_then(|s| Address::from_str(&s).ok())
                .or_else(find_sepolia_contract_address)
                .or_else(|| Address::from_str("0xb2a3D05EF6FBBbcd71933bb2239b5954D242f833").ok())
                .context("Sepolia contract address not found! Set SEPOLIA_CONTRACT_ADDRESS or run the deploy.")?;

            println!("Sepolia contract configured: {}", contract);
            println!("RPC URL: {}", rpc_url);

            // Sepolia requires --wallet (already validated) - retrieve it here
            let wallet_private_key = cmd.wallet.clone().expect("wallet already validated but missing");
            Ok(Some(ChainProfile::Sepolia(SepoliaConfig { chain_id, rpc_url, contract, wallet_private_key })))
        }
    }
}



/// Performs on-chain verification of a proof loaded from a file.
/// 
/// This function deserializes a receipt from the specified file path and submits
/// it to the smart contract for verification. The transaction is broadcast to
/// the network specified in the chain profile.
/// 
/// # Arguments
/// 
/// - `path`: Path to the serialized receipt file (bincode format).
/// - `profile`: Network configuration (Anvil or Sepolia).
/// - `metrics`: If true, records transaction metrics to CSV.
/// - `n_runs`: Number of verification transactions to send (for benchmarking).
/// 
/// # File Format
/// 
/// The file must contain a `Receipt` serialized using bincode.
/// These files are automatically created by `generate_proof_for_backend`.
fn exec_verify_onchain_from_file(path: &str, profile: &ChainProfile, metrics: bool, n_runs: usize) {
    println!("Loading proof from file: {}", path);

    // Open and read the proof file
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error opening proof file: {}", e);
            return;
        }
    };
    let mut buffer = Vec::new();
    if let Err(e) = file.read_to_end(&mut buffer) {
        eprintln!("Error reading proof file: {}", e);
        return;
    }

    // Deserialize the receipt from bincode format
    let receipt: Receipt = match bincode::deserialize(&buffer) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error deserializing proof: {}", e);
            return;
        }
    };

    // Extract connection parameters from the chain profile
    let (rpc_url, contract_addr, key) = match profile {
        ChainProfile::Anvil(cfg) => (cfg.rpc_url.clone(), cfg.contract, cfg.signer_private_key.clone()),
        ChainProfile::Sepolia(cfg) => (cfg.rpc_url.clone(), cfg.contract, cfg.wallet_private_key.clone()),
    };

    if let Err(e) = run_onchain_verification(&receipt, contract_addr, &key, rpc_url, path, metrics, n_runs) {
        eprintln!("Error during on-chain verification: {:?}", e);
    } else {
        println!("On-chain verification from file completed successfully.");
    }
}



/// Core on-chain verification logic.
/// 
/// This function handles the complete lifecycle of submitting a proof to an
/// Ethereum smart contract for verification:
/// 
/// 1. **Wallet Setup**: Initializes a signer from the provided private key.
/// 2. **Seal Encoding**: Converts the receipt into the format expected by the verifier contract.
/// 3. **Transaction Submission**: Calls the contract's `set(journal, seal)` function.
/// 4. **Receipt Confirmation**: Waits for the transaction to be mined and retrieves the result.
/// 5. **Metrics Recording**: Logs gas usage, timing, and success rate.
/// 
/// # Contract Interface
/// 
/// The function calls `set(bytes journal, bytes seal)` on the contract, which:
/// - Verifies the RISC Zero proof using the on-chain verifier.
/// - Stores the journal data if verification succeeds.
/// - Reverts if verification fails.
/// 
/// # Arguments
/// 
/// - `receipt`: The cryptographic proof to verify.
/// - `contract_address`: Address of the deployed verification contract.
/// - `signer_key`: Private key for signing transactions (hex format).
/// - `rpc_url`: Ethereum RPC endpoint.
/// - `metrics`: If true, records detailed metrics.
/// - `n_runs`: Number of transactions to send (for benchmarking throughput).
/// 
/// # Returns
/// 
/// - `Ok(())`: All transactions completed (check logs for individual success/failure).
/// - `Err`: If wallet setup, encoding, or transaction submission fails.
fn run_onchain_verification(
    receipt: &Receipt,
    contract_address: Address,
    signer_key: &str,
    rpc_url: Url,
    input_id: &str,
    metrics: bool,
    n_runs: usize,
) -> Result<()> {
    // Initialize wallet and provider from the signer key
    let signer = PrivateKeySigner::from_str(signer_key)
        .context("Invalid private key")?;
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url);

    // Encode the cryptographic seal into the format expected by the verifier contract
    let seal = encode_seal(receipt).context("Seal encoding failed")?;
    let journal = receipt.journal.bytes.clone();

    // Initialize the contract interface
    let contract = IContract::new(contract_address, provider);
    
    // Create async runtime for blockchain interactions
    let runtime = tokio::runtime::Runtime::new()?;

    // Setup metrics files
    let timestamp = Local::now().format("%d_%m_%y_%H_%M").to_string();
    let mut tx_trace = if metrics {
        std::fs::create_dir_all("metrics")?;
        let filename = format!("metrics/tx_trace_metrics_{}.csv", timestamp);
        let f = File::options().append(true).create(true).open(&filename)?;
        if f.metadata()?.len() == 0 {
            let mut f_ref = &f;
            writeln!(f_ref, "input_id,tx_hash,gas_used,gas_price,block_number,time_ms,success")?;
        }
        Some(f)
    } else {
        None
    };

    let mut verify_metrics_log = if metrics {
        std::fs::create_dir_all("metrics")?;
        let filename = format!("metrics/verify_metrics_{}.csv", timestamp);
        let f = File::options().append(true).create(true).open(&filename)?;
        if f.metadata()?.len() == 0 {
            let mut f_ref = &f;
            writeln!(f_ref, "input_id,avg_gas_used,avg_gas_price,avg_time_ms,success_pct")?;
        }
        Some(f)
    } else {
        None
    };

    let mut times = Vec::new();
    let mut successes = 0;
    let mut gas_used = Vec::new();
    let mut gas_price = Vec::new();
    
    println!("Starting on-chain verification ({} transactions)...", n_runs);
    for i in 0..n_runs {
        // Call the contract's set(bytes journal, bytes seal) function
        let call_builder = contract.set(journal.clone().into(), seal.clone().into());
        
        let t_start = Instant::now();
        
        // Send transaction
        let pending_tx = runtime.block_on(call_builder.send())
            .context(format!("Error sending transaction {}", i+1))?;
            
        // Wait for transaction receipt
        let tx_receipt = runtime.block_on(pending_tx.get_receipt())
            .context(format!("Error retrieving receipt for transaction {}", i+1))?;
            
        let duration_ms = t_start.elapsed().as_millis();
        let success = tx_receipt.status();
        
        if success { successes += 1; }
        
        let g_used = tx_receipt.gas_used;
        let g_price = tx_receipt.effective_gas_price;
        
        times.push(duration_ms);
        gas_used.push(g_used);
        gas_price.push(g_price);

        println!("Tx {}/{}: hash={:?}, success={}, gas={}, time={}ms", 
            i+1, n_runs, tx_receipt.transaction_hash, success, g_used, duration_ms);

        if let Some(ref mut f) = tx_trace {
            writeln!(f, "{},{:?},{},{},{},{},{}",
                input_id,
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
        let success_rate = (successes as f64 / n_runs as f64) * 100.0;
        
        writeln!(f, "{},{},{},{},{:.2}", input_id, avg_gas, avg_price, avg_time, success_rate)?;
    }

    Ok(())
}

/// Verifies a proof locally using the RISC Zero verifier.
/// 
/// Off-chain verification is fast and free, making it ideal for:
/// - Development and debugging.
/// - Pre-flight checks before on-chain submission.
/// - Scenarios where on-chain attestation is not required.
/// 
/// # Verification Process
/// 
/// 1. Calls `receipt.verify(GUEST_ID)` to cryptographically verify the proof.
/// 2. Checks that the proof was generated by the expected guest program (identified by `GUEST_ID`).
/// 3. Validates the cryptographic seal against the journal contents.
/// 
/// # Arguments
/// 
/// - `receipt`: The proof to verify.
/// - `source_label`: Descriptive label for the proof source (used in logging and metrics).
/// - `metrics`: If true, records verification timing to CSV.
/// 
/// # Security Note
/// 
/// A successful off-chain verification guarantees that:
/// - The guest program executed correctly with the journal as output.
/// - The proof is cryptographically valid.
/// 
/// It does NOT provide on-chain attestation or prevent the prover from
/// discarding invalid proofs before showing valid ones.
fn verify_receipt_offchain(receipt: &Receipt, input_id: &str, metrics: bool) {
    println!("Starting off-chain verification (input_id: {})...", input_id);
    let t_start = Instant::now();
    
    match receipt.verify(GUEST_ID) {
        Ok(()) => {
            let duration = t_start.elapsed().as_millis();
            println!("Off-chain verification completed successfully in {}ms", duration);
            
            if metrics {
                 let _ = std::fs::create_dir_all("metrics");
                 let timestamp = Local::now().format("%d_%m_%y_%H_%M").to_string();
                 let filename = format!("metrics/verify_offchain_metrics_{}.csv", timestamp);
                 if let Ok(mut f) = File::options().append(true).create(true).open(&filename) {
                    if f.metadata().map(|m| m.len() == 0).unwrap_or(false) {
                        let _ = writeln!(f, "input_id,success,time_ms");
                    }
                    let _ = writeln!(f, "{},true,{}", input_id, duration);
                }
            }
        },
        Err(e) => {
            let duration = t_start.elapsed().as_millis();
            eprintln!("Off-chain verification FAILED: {:?}", e);
             if metrics {
                 let _ = std::fs::create_dir_all("metrics");
                 let timestamp = Local::now().format("%d_%m_%y_%H_%M").to_string();
                 let filename = format!("metrics/verify_offchain_metrics_{}.csv", timestamp);
                 if let Ok(mut f) = File::options().append(true).create(true).open(&filename) {
                    if f.metadata().map(|m| m.len() == 0).unwrap_or(false) {
                        let _ = writeln!(f, "input_id,success,time_ms");
                    }
                    let _ = writeln!(f, "{},false,{}", input_id, duration);
                }
            }
        }
    }
}

// Off-chain verification from file
fn exec_verify_offchain_from_file_stub(path: &str, metrics: bool) {
    println!("Loading proof from file: {}", path);
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error opening proof file: {}", e);
            return;
        }
    };
    let mut buffer = Vec::new();
    if let Err(e) = file.read_to_end(&mut buffer) {
        eprintln!("Error reading proof file: {}", e);
        return;
    }

    let receipt: Receipt = match bincode::deserialize(&buffer) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error deserializing proof: {}", e);
            return;
        }
    };

    // Use the file path as input_id for metrics tracking
    verify_receipt_offchain(&receipt, path, metrics);
}

// Off-chain verification with proof generated in this session
fn exec_verify_offchain_from_new_stub(receipts: &[(Backend, Receipt)], input_hash: &str, metrics: bool) {
    if receipts.is_empty() {
        println!("No proof available for off-chain verification.");
        return;
    }
    for (_backend, receipt) in receipts {
        verify_receipt_offchain(receipt, input_hash, metrics);
    }
}

// On-chain verification with proof generated in this session
fn exec_verify_onchain_from_new_stub(
    receipt: Option<&Receipt>,
    profile: &ChainProfile,
    input_id: &str,
    metrics: bool,
    n_runs: usize
) -> Result<()> {
    let (rpc_url, contract_addr, key) = match profile {
        ChainProfile::Anvil(cfg) => (cfg.rpc_url.clone(), cfg.contract, cfg.signer_private_key.clone()),
        ChainProfile::Sepolia(cfg) => (cfg.rpc_url.clone(), cfg.contract, cfg.wallet_private_key.clone()),
    };

    if let Some(r) = receipt {
        println!("Starting on-chain verification (Groth16)...");
        if let Err(e) = run_onchain_verification(r, contract_addr, &key, rpc_url, input_id, metrics, n_runs) {
            eprintln!("Error during on-chain verification: {:?}", e);
            return Err(e);
        }
        println!("On-chain verification completed successfully.");
        Ok(())
    } else {
        anyhow::bail!("No Groth16 proof available for on-chain verification");
    }
}


// Main entry point
fn main() -> Result<()> {

    // Parse command line arguments
    let cli = Cli::parse();
    match cli.command {
        Commands::Run(RunCmd { input, input_file, session, prove, verify, network, source, proof_file, wallet, n_runs, metrics }) => {
            // Resolve input: either from --input or --input-file
            let resolved_input: Option<String> = match (&input, &input_file) {
                (Some(i), None) => Some(i.clone()),
                (None, Some(path)) => {
                    let mut file = File::open(path)
                        .map_err(|e| anyhow::anyhow!("Failed to open input file '{}': {}", path, e))?;
                    let mut contents = String::new();
                    file.read_to_string(&mut contents)
                        .map_err(|e| anyhow::anyhow!("Failed to read input file '{}': {}", path, e))?;
                    Some(contents.trim().to_string())
                },
                (None, None) => None,
                (Some(_), Some(_)) => unreachable!("clap conflicts_with prevents this"),
            };

            // Cross-validate required flag combinations
            validate_run(&RunCmd {
                input: resolved_input.clone(),
                input_file: None, // Already resolved above
                session,
                prove: prove.clone(),
                verify,
                network,
                source,
                proof_file: proof_file.clone(),
                wallet: wallet.clone(),
                n_runs,
                metrics,
            })?;

            // DEBUG: print acquired parameters from command line
            println!("Detected configuration:");
            println!("Input: {:?}", resolved_input);
            println!("Session: {}", session);
            let provers: Vec<&'static str> = prove
                .iter()
                .map(|backend| match backend { Backend::Stark => "stark", Backend::Groth16 => "groth16" })
                .collect();
            println!("Prove backends: {:?}", provers);
            println!("Verify: {:?}", verify);
            println!("Network: {:?}", network);
            println!("Source: {:?}", source);
            println!("Proof file: {:?}", proof_file);
            println!("Wallet: {}", if wallet.is_some() { "[provided]" } else { "-" });
            println!("N. Transactions: {}", n_runs);
            println!("Metrics: {}", metrics);

            // Parse and validate input (if present)
            let typed_input_opt: Option<TypedInput> = match &resolved_input {
                Some(spec) => Some(parse_typed_input(spec).map_err(|e| anyhow::anyhow!("Input error: {}", e))?),
                None => None,
            };

            // Dispatcher stub (session, proving, verify)

            // Single ABI encoding if needed (session or prove or source=new)
            let encoded_input_opt: Option<Vec<u8>> = typed_input_opt.as_ref().map(|ti| match &ti.validated {
                ValidatedSolData::Uint256(n) => n.abi_encode(),
                ValidatedSolData::Uint256Triple(b,e,m) => (b.clone(),e.clone(),m.clone()).abi_encode(),
                ValidatedSolData::String(s) => s.clone().abi_encode(),
                ValidatedSolData::Bytes(b) => Bytes::from(b.clone()).abi_encode(),
                ValidatedSolData::Bool(v) => v.abi_encode(),
                ValidatedSolData::Address(a) => a.abi_encode(),
                // bytesN is encoded as fixed-bytes (32) ABI word, not as dynamic bytes
                ValidatedSolData::BytesN(arr,_) => {
                    let mut padded = [0u8; 32];
                    let len = arr.len();
                    padded[..len].copy_from_slice(arr);
                    FixedBytes::<32>::from(padded).abi_encode()
                },
                // MerkleProof: ABI encode as (bytes32, bytes32[], bool[], bytes32)
                ValidatedSolData::MerkleProof { leaf, siblings, directions, expected_root } => {
                    let leaf_fb = FixedBytes::<32>::from(*leaf);
                    let siblings_fb: Vec<FixedBytes<32>> = siblings.iter()
                        .map(|s| FixedBytes::<32>::from(*s))
                        .collect();
                    let root_fb = FixedBytes::<32>::from(*expected_root);
                    (leaf_fb, siblings_fb, directions.clone(), root_fb).abi_encode()
                },
            });

            // Session generation
            if session {
                if let (Some(encoded_input), Some(_ti)) = (&encoded_input_opt, &typed_input_opt) {
                    let original_spec = resolved_input.as_deref().unwrap_or("");
                    let _session = exec_session_stub(encoded_input, original_spec, metrics)?;
                }
            }

            // Proof generation (replaces stub)
            let mut generated_receipts: Vec<(Backend, Receipt)> = Vec::new();
            let mut groth16_receipt: Option<Receipt> = None;
            if !prove.is_empty() {
                if let (Some(encoded_input), Some(_ti)) = (&encoded_input_opt, &typed_input_opt) {
                    let original_spec = resolved_input.as_deref().unwrap_or("");
                    for backend in &prove {
                       let receipt = generate_proof_for_backend(*backend, encoded_input, original_spec, metrics)?;
                        if *backend == Backend::Groth16 {   
                            groth16_receipt = Some(receipt.clone());
                        }
                        generated_receipts.push((*backend, receipt));
                    }
                }
            }
            
            // Proof verification
            if let Some(vmode) = verify {
                match (source, vmode) {
                    // Import proof from file
                    // Offchain
                    (Some(VerifySource::File), VerifyMode::Offchain) => {
                        if let Some(path) = &proof_file { exec_verify_offchain_from_file_stub(path, metrics); }
                    }
                    // Onchain
                    (Some(VerifySource::File), VerifyMode::Onchain) => {
                        if let Some(path) = &proof_file {
                            let profile = build_chain_profile(&RunCmd { input: input.clone(), input_file: None, session, prove: prove.clone(), verify, network, source, proof_file: proof_file.clone(), wallet: wallet.clone(), n_runs, metrics })?
                                .expect("On-chain profile missing");
                            exec_verify_onchain_from_file(path, &profile, metrics, n_runs);
                        }
                    }
                    // Proof generated in current execution
                    // Offchain 
                    (Some(VerifySource::New), VerifyMode::Offchain) => {
                        // Local verification of all freshly generated proofs (all requested backends)
                        if let Some(encoded_input) = &encoded_input_opt {
                            let input_hash = compute_input_hash(encoded_input);
                            exec_verify_offchain_from_new_stub(&generated_receipts, &input_hash, metrics);
                        }
                    }
                    // Onchain (only groth16)
                    (Some(VerifySource::New), VerifyMode::Onchain) => {
                        // On-chain: verify only Groth16 proofs
                        let profile = build_chain_profile(&RunCmd { input: input.clone(), input_file: None, session, prove: prove.clone(), verify, network, source, proof_file: proof_file.clone(), wallet: wallet.clone(), n_runs, metrics })?
                            .expect("On-chain profile missing");
                        if let Some(encoded_input) = &encoded_input_opt {
                            let input_hash = compute_input_hash(encoded_input);
                            exec_verify_onchain_from_new_stub(groth16_receipt.as_ref(), &profile, &input_hash, metrics, n_runs)?;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

