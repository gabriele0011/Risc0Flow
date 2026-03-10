# Risc0Flow

**Risc0Flow** is a framework for orchestrating applications based on RISC Zero's zkVM, designed to offer complete automation of operations and additional development tools essential for building applications with RISC Zero. It simplifies interaction with the zkVM by providing a unified interface for generating sessions, producing cryptographic proofs, and validating them on blockchain (Ethereum ecosystem), while keeping every step configurable. 

It is conceived as an **operations toolkit** that can be executed individually, combined into a single continuous flow, or decoupled.

<br>

## Main Features

The framework offers the following operational advantages:

* **Unified CLI orchestration:** It provides a command-line interface to dynamically configure the execution (Session), proof generation (Proving), and validation (Verification) phases without having to modify the host code.
* **Process decoupling:** It allows executing the phases independently, pausing and resuming the workflow to enable scenarios such as remote proving and deferred verification over time.
* **Automated ABI management (Type Safety):** It ensures a perfect match between the zkVM input and the expected smart contract output by automatically converting the data provided via CLI into a typed, ABI-encoded format.
* **Proving and verification flexibility:** It supports multiple backends for receipt generation (STARK and Groth16) and handles distinct paths for local verification (off-chain) or through automated transactions on Ethereum networks like Anvil and Sepolia.
* **Generic smart contract and Auto-Discovery:** It implements a universal smart contract capable of validating proofs from any Guest logic without requiring modifications to the Solidity code. It also automatically detects deployment addresses through Service Discovery mechanisms.
* **Observability and metrics:** It integrates a native system for performance tracking that can be exported to CSV. This provides detailed reports on execution times, memory consumption, CPU cycles, and gas estimates.

<br>

## � Getting Started — Step by Step

This section guides you through the complete workflow, from writing your first guest program to on-chain verification.

### Step 0 — Write the Guest Code

The guest program is the Rust code that runs inside the zkVM. This is where your provable logic lives.

Edit the file `methods/guest/src/bin/guest.rs` with your custom logic. A working example is already included as a starting point. For a detailed guide on the I/O pattern (input decoding, ABI-encoded output, commitment), see [methods/guest/README.md](methods/guest/README.md).

<br>

### Step 1 — Compile the Project

After writing (or modifying) the guest code, compile the entire workspace. This step builds the guest binary for the RISC-V target, generates the `ImageID` and `ELF` Solidity contracts, and compiles the host.

```bash
RISC0_USE_DOCKER=1 cargo build --release
```

> **Note:** The first build downloads the RISC Zero toolchain and may take several minutes.
>
> **`RISC0_USE_DOCKER=1`** ensures the guest binary is built inside a Docker container, producing a deterministic `ImageID`. This is **required** for on-chain verification (the `ImageID` must match exactly). You can omit it for local-only or off-chain workflows.
>
> **Development tip:** Use `cargo check` for the fastest feedback loop (no binaries produced), `cargo build` for quick debug builds, and `cargo build --release` when you're ready to run proving or verification workloads — debug mode is orders of magnitude slower.
>
> After building, the binary is available at `./target/release/host`. All commands below use it directly to avoid the overhead of `cargo run` (which re-checks compilation on every invocation).

<br>

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

<br>

### Step 3 — Run Risc0Flow

Use the `host` binary with the appropriate flags depending on your workflow. For a complete reference of all available flags, input types, and validation rules, see [CLI.md](CLI.md).

**Session only (test the guest logic):**
```bash
./target/release/host run --input '<u256; 42>' --session
```

**Generate a proof (STARK or Groth16):**
```bash
./target/release/host run --input '<u256; 42>' --prove stark
./target/release/host run --input '<u256; 42>' --prove groth16
# Output saved in: proofs/receipt_<backend>_<timestamp>.bin
```

**Off-chain verification (from a saved proof):**
```bash
./target/release/host run --source file --proof-file proofs/receipt_stark_<timestamp>.bin --verify offchain
```

**On-chain verification (Anvil):**
```bash
./target/release/host run --input '<u256; 42>' --prove groth16 --source new --verify onchain --network anvil
```

**On-chain verification (Sepolia):**
```bash
./target/release/host run --input '<u256; 42>' --prove groth16 --source new --verify onchain --network sepolia --wallet $ETH_WALLET_PRIVATE_KEY
```

**Full pipeline with metrics:**
```bash
./target/release/host run --input '<u256; 42>' --prove groth16 --source new --verify onchain --network anvil --metrics
```

**On-chain stress test (multiple verifications):**
```bash
./target/release/host run --source file --proof-file <FILE> --verify onchain --network anvil --n-runs 10 --metrics
```

> **Tip:** Add `--metrics` to any command to export CSV performance data to the `metrics/` folder.

<br>

## 📡 Deploy

The repository includes Bash scripts to simplify the deployment of verification contracts:

- **`deploy_anvil.sh`**: Starts a local Anvil node (if not active) and deploys the contract.
- **`deploy_sepolia.sh`**: Deploys the contract to the Sepolia testnet. Requires an Alchemy API key and a wallet private key (prompted interactively).

<br>

## 📊 Metrics

If enabled via the `--metrics` flag, all execution data is automatically saved in the `/metrics` folder with unique timestamps:
- `session_metrics_*.csv`: Execution times and user cycles.
- `proving_metrics_*.csv`: Proving times, RAM/CPU usage, proof sizes.
- `tx_trace_metrics_*.csv`: Transaction hashes, gas used, gas price, and success status.
- `verify_metrics_*.csv`: Aggregate on-chain verification statistics (average gas, average time, success rate).

For a complete description of every column, unit, and collection method, see [METRICS.md](METRICS.md).

<br>

## 🛠️ Custom Development (Guest Code)

For details on how to write and integrate your application logic into the Guest, consult the dedicated documentation in [methods/guest/README.md](methods/guest/README.md).

<br>

## 🙏 Acknowledgements

This project was built upon the [risc0-foundry-template](https://github.com/risc0/risc0-foundry-template) released by [RISC Zero](https://risczero.com). We are grateful for their work and for providing an open and solid foundation that made the development of Risc0Flow possible.
