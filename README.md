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

## � Getting Started — Step by Step

This section guides you through the complete workflow, from writing your first guest program to on-chain verification.

### Step 0 — Write the Guest Code

The guest program is the Rust code that runs inside the zkVM. This is where your provable logic lives.

Edit the file `methods/guest/src/bin/guest.rs` with your custom logic. A working example is already included as a starting point. For a detailed guide on the I/O pattern (input decoding, ABI-encoded output, commitment), see [methods/guest/README.md](methods/guest/README.md).

### Step 1 — Compile the Project

After writing (or modifying) the guest code, compile the entire workspace. This step builds the guest binary for the RISC-V target, generates the `ImageID` and `ELF` Solidity contracts, and compiles the host.

```bash
RISC0_USE_DOCKER=1 cargo build --release
```

> **Note:** The first build downloads the RISC Zero toolchain and may take several minutes.
>
> **`RISC0_USE_DOCKER=1`** ensures the guest binary is built inside a Docker container, producing a deterministic `ImageID`. This is **required** for on-chain verification (the `ImageID` must match exactly). You can omit it for local-only or off-chain workflows.
>
> **Important:** Always use `--release` for proving and verification workloads. Debug mode (`cargo build` / `cargo run` without `--release`) is orders of magnitude slower and should only be used for quick compilation checks during development.

### Step 2 — (Optional) Deploy the Verification Contracts

This step is **required only if you intend to verify proofs on-chain**. If you only need off-chain verification, skip to Step 3.

**Local network (Anvil):**
```bash
bash deploy_anvil.sh
```

**Sepolia testnet:**
```bash
bash deploy_sepolia.sh
```

The scripts deploy the verifier and your application contract, then write the relevant environment variables to `.env_vars`.

### Step 3 — Run Risc0Flow

Use the `host` binary with the appropriate flags depending on your workflow.

**Session only (test the guest logic):**
```bash
cargo run --release --bin host -- run --input '<u256; 42>' --session
```

**Generate a proof (STARK or Groth16):**
```bash
cargo run --release --bin host -- run --input '<u256; 42>' --prove stark
cargo run --release --bin host -- run --input '<u256; 42>' --prove groth16
# Output saved in: proofs/receipt_<backend>_<timestamp>.bin
```

**Off-chain verification (from a saved proof):**
```bash
cargo run --release --bin host -- run --source file --proof-file proofs/receipt_stark_<timestamp>.bin --verify offchain
```

**On-chain verification (Anvil):**
```bash
cargo run --release --bin host -- run --input '<u256; 42>' --prove groth16 --source new --verify onchain --network anvil
```

**On-chain verification (Sepolia):**
```bash
cargo run --release --bin host -- run --input '<u256; 42>' --prove groth16 --source new --verify onchain --network sepolia --wallet $ETH_WALLET_PRIVATE_KEY
```

**Full pipeline with metrics:**
```bash
cargo run --release --bin host -- run --input '<u256; 42>' --prove groth16 --source new --verify onchain --network anvil --metrics
```

> **Tip:** Add `--metrics` to any command to export CSV performance data to the `metrics/` folder.

## 📖 Usage Scenarios

### 1. Rapid Development (Guest logic only)
Verify that the guest Rust code works correctly.
```bash
cargo run --release --bin host -- run --input '<u256; 42>' --session
```

### 2. Full Pipeline (All-in-One)
Generate the proof and verify on-chain.
```bash
cargo run --release --bin host -- run --input '<u256; 42>' --prove groth16 --source new --verify onchain --network sepolia --wallet $ETH_WALLET_PRIVATE_KEY
```

### 3. Decoupled Workflow (Remote Proving / Deferred Verification)

**Step A: Generation**
Generate the proof and export it to a binary file.
```bash
cargo run --release --bin host -- run --input '<u256; 42>' --prove groth16
# Output saved in: proofs/receipt_groth16_<timestamp>.bin
```

**Step B: Verification**
Take the generated file and verify the relative proof on-chain.
```bash
cargo run --release --bin host -- run --source file --proof-file proofs/receipt_groth16_<timestamp>.bin --verify onchain --network sepolia --wallet $ETH_WALLET_PRIVATE_KEY
```

### 4. On-Chain Stress Test
Run multiple verifications to test contract stability or calculate average gas.
```bash
cargo run --release --bin host -- run --source file --proof-file <FILE> --verify onchain --network anvil --n-runs 10 --metrics
```

## ️ Deploy

The repository includes Bash scripts to simplify the deployment of verification contracts:

- **`deploy_anvil.sh`**: Starts a local Anvil node (if not active) and deploys the contract.
- **`deploy_sepolia.sh`**: Deploys the contract to the Sepolia testnet. Requires an Alchemy API key and a wallet private key (prompted interactively).

## 📊 Metrics

If enabled via the `--metrics` flag, all execution data is automatically saved in the `/metrics` folder with unique timestamps:
- `session_metrics_*.csv`: Execution times and user cycles.
- `proving_metrics_*.csv`: Proving times, RAM/CPU usage, proof sizes.
- `tx_trace_metrics_*.csv`: Transaction hashes, gas used, gas price, and success status.
- `verify_metrics_*.csv`: Aggregate on-chain verification statistics (average gas, average time, success rate).

## 🛠️ Custom Development (Guest Code)

For details on how to write and integrate your application logic into the Guest, consult the dedicated documentation in [methods/guest/README.md](methods/guest/README.md).


