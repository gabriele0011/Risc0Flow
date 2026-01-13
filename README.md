# Risc0Flow

**Risc0Flow** is a framework for orchestrating applications based on RISC Zero's zkVM, designed to offer complete automation of operations and additional development tools essential for building applications with RISC Zero. It simplifies interaction with the zkVM by providing a unified interface for generating sessions, producing cryptographic proofs, and validating them on blockchain (Ethereum ecosystem), while keeping every step configurable. 

It is conceived as an **operations toolkit** that can be executed individually, combined into a single continuous flow, or decoupled.

## 🚀 Key Features

- **Modular Architecture**: Run sessions, proving, and verification independently or combined.
- **Multi-Backend Support**: Generate **STARK** proofs (fast and locally verifiable) or **Groth16** proofs (compact and verifiable on-chain).
- **Local Proving**: Currently optimized for CPU-bound workloads executed locally.
- **Integrated On-Chain Verification**: Native interaction with Ethereum (Anvil, Sepolia) via Alloy.
- **Detailed Metrics**: Optional export (`--metrics`) of CSV files for performance analysis (time, RAM, CPU, Gas) across various phases.

## 🧩 Modular Architecture

The framework is designed to adapt to any need, allowing for both linear and granular execution:

1.  **Session & Debugging (`--session`)**: Executes only the guest program written in Rust.
2.  **Proving (`--prove`)**: Generates proofs (STARK/Groth16). It can be executed as an intermediate step (saving the proof to disk) or as part of a continuous pipeline.
3.  **Verification (`--verify`)**: Validates the proof off-chain or on-chain. This can happen immediately after the generation phase or at a later time by loading the file (corresponding to the exported proof) from disk.

## 📖 Usage Scenarios

### 1. Rapid Development (Guest logic only)
Verify that the guest Rust code works correctly.
```bash
host run --input '<u256; 42>' --session
```

### 2. Full Pipeline (All-in-One)
Generate the proof and verify on-chain.
```bash
host run --input '<u256; 42>' --prove groth16 --source new --verify onchain --network sepolia --wallet $PRIVATE_KEY
```

### 3. Decoupled Workflow (Remote Proving / Deferred Verification)

**Step A: Generation**
Generate the proof and export it to a binary file.
```bash
host run --input '<u256; 42>' --prove groth16
# Output saved in: proofs/receipt_groth16_<timestamp>.bin
```

**Step B: Verification**
Take the generated file and verify the relative proof on-chain.
```bash
host run --source file --proof-file proofs/receipt_groth16_<timestamp>.bin --verify onchain --network sepolia --wallet $PRIVATE_KEY
```

### 4. On-Chain Stress Test
Run multiple verifications to test contract stability or calculate average gas.
```bash
host run --source file --proof-file <FILE> --verify onchain --network anvil --n-runs 10 --metrics
```

## ️ Deploy

The repository includes Bash scripts to simplify the deployment of verification contracts:

- **`deploy_local.sh`**: Starts a local Anvil node (if not active) and deploys the contract.
- **`deploy_sepolia.sh`**: Deploys the contract to the Sepolia testnet.

## 📊 Metrics

If enabled via the `--metrics` flag, all execution data is automatically saved in the `/metrics` folder with unique timestamps:
- `session_metrics_*.csv`: Execution times and user cycles.
- `proving_metrics_*.csv`: Proving times, RAM/CPU usage, proof sizes.
- `tx_trace_metrics_*.csv`: Transaction hashes, gas used, gas price, and success status.
- `verify_metrics_*.csv`: Aggregate on-chain verification statistics (average gas, average time, success rate).

## 🛠️ Custom Development (Guest Code)

For details on how to write and integrate your application logic into the Guest, consult the dedicated documentation in [methods/guest/README.md](methods/guest/README.md).


