# Metrics Reference

When the `--metrics` flag is enabled, the host collects detailed performance data at each stage of the pipeline and saves it as CSV files in the `metrics/` directory.

```bash
# Example usage
./target/release/host run --input '<u256; 0x01>' --prove stark groth16 --metrics
```

---

## 1. Session Metrics

**File:** `metrics/session_metrics_<timestamp>.csv`

Recorded during guest execution in the zkVM (`--session` or `--prove`).

| Column | Unit | Description |
|--------|------|-------------|
| `input_id` | hex (8 char) | Truncated SHA-256 hash of the ABI-encoded input |
| `time_ms` | ms | Guest execution time inside the zkVM |
| `user_cycles` | count | Number of zkVM cycles consumed |

---

## 2. Proving Metrics

**File:** `metrics/proving_metrics_<timestamp>.csv`

Recorded during proof generation (`--prove`).

| Column | Unit | Description |
|--------|------|-------------|
| `input_id` | hex (8 char) | Input hash |
| `backend` | — | Proving backend used (`stark` or `groth16`) |
| `phase` | — | Pipeline phase (always `prove`) |
| `time_ms` | ms | Total proof generation time |
| `seal_size` | bytes | Size of the cryptographic seal |
| `journal_len` | bytes | Size of the public journal |
| `receipt_bincode_len` | bytes | Size of the bincode-serialized receipt |
| `peak_ram_kb` | KB | Peak process RSS (Resident Set Size) during proving |
| `avg_cpu_pct` | % | Average CPU utilization (can exceed 100% on multi-core) |
| `max_cpu_pct` | % | Peak CPU utilization |
| `max_threads` | count | Maximum number of concurrent threads observed |

> **Note:** The system-level metrics (`peak_ram_kb`, `avg_cpu_pct`, `max_cpu_pct`, `max_threads`) are collected by a background monitoring thread that samples the process every 500 ms using Welford's online algorithm for numerically stable incremental averaging.

---

## 3. Off-chain Verification Metrics

**File:** `metrics/verify_offchain_metrics_<timestamp>.csv`

Recorded during local proof verification (`--verify offchain`).

| Column | Unit | Description |
|--------|------|-------------|
| `input_id` | — | Input hash or proof file path |
| `success` | bool | Verification outcome (`true` / `false`) |
| `time_ms` | ms | Local verification time |

---

## 4. On-chain Verification — Transaction Trace

**File:** `metrics/tx_trace_metrics_<timestamp>.csv`

Recorded for each individual transaction during on-chain verification (`--verify onchain`).

| Column | Unit | Description |
|--------|------|-------------|
| `input_id` | — | Input identifier |
| `tx_hash` | hex | Ethereum transaction hash |
| `gas_used` | gas units | Gas consumed by the transaction |
| `gas_price` | wei | Effective gas price |
| `block_number` | — | Block number containing the transaction |
| `time_ms` | ms | Time from submission to confirmation |
| `success` | bool | Transaction outcome |

---

## 5. On-chain Verification — Aggregate Summary

**File:** `metrics/verify_metrics_<timestamp>.csv`

Aggregated statistics over all transactions in an on-chain verification run.

| Column | Unit | Description |
|--------|------|-------------|
| `input_id` | — | Input identifier |
| `avg_gas_used` | gas units | Average gas consumed across all transactions |
| `avg_gas_price` | wei | Average effective gas price |
| `avg_time_ms` | ms | Average time per transaction |
| `success_pct` | % | Percentage of successful transactions |

---

## 6. Input Reference

**File:** `metrics/input_<hash>.csv`

Maps input hashes (used in all other CSV files) back to the original input specification.

| Column | Description |
|--------|-------------|
| `input_id` | Input hash |
| `input_spec` | Original input string as provided via `--input` |

This file is created once per unique input and is never overwritten.

---

## File Naming Convention

All metric files use a timestamp in the format `DD_MM_YY_HH_MM` (e.g., `session_metrics_15_02_26_14_30.csv`).

## Directory Structure

```
metrics/
├── session_metrics_<timestamp>.csv
├── proving_metrics_<timestamp>.csv
├── verify_offchain_metrics_<timestamp>.csv
├── tx_trace_metrics_<timestamp>.csv
├── verify_metrics_<timestamp>.csv
└── input_<hash>.csv
```

