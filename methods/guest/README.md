# 🛠️ Guest Code Development

The **Guest Code** is the Rust program that runs inside RISC Zero's zkVM. Everything executed here is cryptographically provable: the zkVM generates a proof that the code ran correctly on the given inputs, without revealing the inputs themselves.

The file to edit is:

```
methods/guest/src/bin/guest.rs
```

A working example (Merkle proof verification) is already included. You can use it as a reference or replace it entirely with your own logic.

---

## 📐 Architecture Overview

The guest program follows a strict **3-phase pattern** that ensures compatibility with Risc0Flow and on-chain verification:

```
┌─────────────────────────────────────────────────────┐
│  HOST (Risc0Flow)                                   │
│  Reads --input, ABI-encodes it, sends to zkVM       │
└───────────────────────┬─────────────────────────────┘
                        │ raw bytes (stdin)
                        ▼
┌─────────────────────────────────────────────────────┐
│  GUEST (your code)                                  │
│  Phase 1: Read & decode input                       │
│  Phase 2: Execute your logic                        │
│  Phase 3: Commit the result to the journal          │
└───────────────────────┬─────────────────────────────┘
                        │ journal (public output)
                        ▼
┌─────────────────────────────────────────────────────┐
│  VERIFIER (off-chain or smart contract)             │
│  Verifies the proof + reads the journal             │
└─────────────────────────────────────────────────────┘
```

---

## Phase 1 — Read & Decode Input

The host sends data to the guest as **ABI-encoded raw bytes** via stdin. You must read them into a buffer and decode using Alloy types.

```rust
use std::io::Read;
use risc0_zkvm::guest::env;
use alloy_sol_types::SolValue;

// Read raw bytes from the host
let mut input_bytes = Vec::<u8>::new();
env::stdin().read_to_end(&mut input_bytes).unwrap();

// Decode according to the expected ABI type
// Example: a single uint256
let value = <U256>::abi_decode(&input_bytes).expect("ABI decode failed");

// Example: a tuple of (uint256, address)
let (amount, addr) = <(U256, Address)>::abi_decode(&input_bytes).expect("ABI decode failed");
```

> **How input reaches the guest:** when you run `cargo run --release --bin host -- run --input '<u256; 42>'`, the host parses the `--input` flag, ABI-encodes the value, and writes the bytes to the zkVM's stdin. The guest reads those bytes with `env::stdin()`.

### Supported `--input` types

| Type | CLI example | Decoded Rust type |
|---|---|---|
| `u256` | `'<u256; 42>'` or `'<u256; 0xFF>'` | `U256` |
| `string` | `'<string; hello>'` | `String` |
| `bytes` | `'<bytes; 0xDEAD>'` | `Vec<u8>` |
| `bool` | `'<bool; true>'` | `bool` |
| `address` | `'<address; 0x1234...>'` | `Address` |
| `bytes32` | `'<bytes32; 0xABCD...>'` | `FixedBytes<32>` |
| `merkle_proof` | `'<merkle_proof; leaf=0x..., ...>'` | `(FixedBytes<32>, Vec<FixedBytes<32>>, Vec<bool>, FixedBytes<32>)` |

---

## Phase 2 — Your Application Logic

This is where you write whatever computation you want to prove. You can use any pure Rust code — no restrictions other than what the `riscv32im` target supports (no filesystem, no networking, no randomness).

```rust
// Example: check that a number is even
assert!(value % U256::from(2) == U256::ZERO, "Value is not even");
let result = value / U256::from(2);
```

> **Important:** If you `assert!` or `panic!`, no proof will be generated. This is useful for enforcing constraints — the proof's existence guarantees the assertions passed.

---

## Phase 3 — Commit the Result (Journal)

The **journal** is the public output of the zkVM. Its content is cryptographically bound to the proof: anyone verifying the proof can read the journal and trust it was produced by this exact program.

For on-chain compatibility, Risc0Flow uses a standard format:

```rust
(string type_signature, bytes encoded_value)
```

Here's how to commit:

```rust
use alloy_sol_types::SolValue;

// 1. Define the Solidity type string
let type_info = "uint256";

// 2. ABI-encode the result
let raw_data = result.abi_encode();

// 3. Wrap into the standard journal format and commit
let journal = (type_info, raw_data).abi_encode();
env::commit_slice(&journal);
```

### Journal format reference

| Result type | `type_info` string | Encoding |
|---|---|---|
| Single value | `"uint256"`, `"bool"`, `"bytes32"`, ... | `value.abi_encode()` |
| Tuple | `"(uint256,address)"` | `(val1, val2).abi_encode()` |
| Array | `"uint256[]"` | `vec.abi_encode()` |

> The `type_info` string is used by the on-chain smart contract to decode the journal. Make sure it matches the Solidity types in your `Contract.sol`.

---

## 📝 Minimal Complete Example

A simple guest that takes a `uint256`, checks it's even, and commits the halved result:

```rust
use alloy_primitives::U256;
use alloy_sol_types::SolValue;
use risc0_zkvm::guest::env;
use std::io::Read;

fn main() {
    // Phase 1: Read & decode
    let mut input_bytes = Vec::<u8>::new();
    env::stdin().read_to_end(&mut input_bytes).unwrap();
    let value = <U256>::abi_decode(&input_bytes).expect("ABI decode failed");

    // Phase 2: Logic
    assert!(value % U256::from(2) == U256::ZERO, "Not even!");
    let result = value / U256::from(2);

    // Phase 3: Commit
    let type_info = "uint256";
    let raw_data = result.abi_encode();
    let journal = (type_info, raw_data).abi_encode();
    env::commit_slice(&journal);
}
```
