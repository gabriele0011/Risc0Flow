# CLI Reference

The Risc0Flow host exposes a single subcommand, **`run`**, that combines session execution, proof generation, and verification into one configurable pipeline.

```
USAGE:
    ./target/release/host run [OPTIONS]
```

---

## Flags & Options

| Flag / Option | Type | Required | Default | Description |
|---|---|---|---|---|
| `--input <INPUT_SPEC>` | `string` | When using `--session`, `--prove`, or `--source new` | — | Input specification in the format `<type_1, …, type_n; val_1, …, val_n>`. Mutually exclusive with `--input-file`. |
| `--input-file <INPUT_FILE>` | `path` | Alternative to `--input` for large inputs | — | Path to a file containing the input string. Mutually exclusive with `--input`. |
| `--session` | `flag` | No | `false` | Execute only the guest program inside the zkVM (session & debugging). |
| `--prove <BACKEND>...` | `stark \| groth16` | No | — | Generate one or more proofs. Accepts one or both backends (e.g. `--prove stark groth16`). |
| `--verify <MODE>` | `offchain \| onchain` | No | — | Verification mode. `offchain` verifies locally; `onchain` submits a transaction to Ethereum. |
| `--source <SOURCE>` | `new \| file` | When `--verify` is used | — | Origin of the proof to verify: `new` generates it in the same command, `file` loads it from disk. |
| `--proof-file <FILE>` | `path` | When `--source file` | — | Path to a previously exported proof binary (e.g. `proofs/receipt_stark_*.bin`). |
| `--network <NETWORK>` | `anvil \| sepolia` | When `--verify onchain` | — | Target Ethereum network for on-chain verification. |
| `--wallet <WALLET>` | `hex string` | When `--network sepolia` | — | Private key of the wallet used to sign the verification transaction on Sepolia. |
| `--n-runs <N>` | `integer` | No | `1` | Number of verification transactions to execute (useful for gas averaging / stress tests). |
| `--metrics` | `flag` | No | `false` | Enable CSV metrics export to the `metrics/` folder. See [METRICS.md](METRICS.md) for details. |

---

## Supported Input Types

The `--input` value uses a Solidity-compatible type syntax:

```
<type; value>
```

| Type | Example |
|---|---|
| `uint256` / `uint<M>` (M = 8–256, multiples of 8) | `<u256; 42>`, `<uint8; 255>` |
| `(uint256, uint256, uint256)` — triple | `<(uint256,uint256,uint256); 2, 3, 5>` |
| `string` | `<string; hello world>` |
| `bytes` | `<bytes; 0xdeadbeef>` |
| `bytes<N>` (N = 1–32) | `<bytes32; 0x00…>` |
| `bool` | `<bool; true>` |
| `address` | `<address; 0xAbC…>` |
| `merkle_proof` | Custom Merkle membership proof |

---

## Validation Rules

The CLI enforces logical consistency between flags before execution:

1. At least one of `--session`, `--prove`, or `--verify` must be specified.
2. `--verify` requires `--source` (`new` or `file`).
3. `--verify onchain` requires `--network`.
4. `--source new` requires `--prove` and `--input`.
5. `--source file` requires `--proof-file`.
6. On-chain verification requires a `groth16` proof.
7. `--network sepolia` requires `--wallet`.
8. `--source new` is incompatible with `--proof-file`; `--source file` is incompatible with `--input`.
9. `--wallet` is only valid with `--verify onchain --network sepolia`.

---

## Examples

**Session only (test the guest logic):**
```bash
./target/release/host run --input '<u256; 42>' --session
```

**Generate proofs with both backends:**
```bash
./target/release/host run --input '<u256; 42>' --prove stark groth16
```

**Off-chain verification from file:**
```bash
./target/release/host run --source file --proof-file proofs/receipt_stark_*.bin --verify offchain
```

**On-chain verification on Anvil (fresh proof):**
```bash
./target/release/host run --input '<u256; 42>' --prove groth16 --source new --verify onchain --network anvil
```

**On-chain verification on Sepolia (fresh proof):**
```bash
./target/release/host run --input '<u256; 42>' --prove groth16 --source new --verify onchain --network sepolia --wallet 0xYOUR_PRIVATE_KEY
```

**On-chain stress test with metrics:**
```bash
./target/release/host run --source file --proof-file proofs/proof.bin --verify onchain --network anvil --n-runs 10 --metrics
```
