# 🛠️ Guest Code Development

**Guest Code** is the part of the application that runs inside the zkVM. This is where the logic you want to cryptographically prove resides.

## 📌 Key Concepts

To ensure your program is compatible with Risc0Flow's on-chain verification system, you must follow a specific Input/Output flow.

### 1. Input (Host to Guest)
The Host sends data to the Guest as a sequence of **raw bytes** (ABI-encoded).
*   **What to do**: Use `env::stdin().read_to_end(&mut buffer)` to read raw bytes into a vector, then decode them using `Alloy` (e.g., `<(Type1, Type2)>::abi_decode(&buffer)`).
*   **Why**: This allows passing complex data structures (tuples, arrays, structs) in a standardized way.

### 2. Application Logic
Once the data is decoded, you can perform any pure Rust computation.

### 3. Output (Guest to Verifier)
The calculation result must be made "public" (committed to the Journal) in a format compatible with an Ethereum smart contract.
*   **Required Format**: An ABI-encoded tuple: `(string type_signature, bytes encoded_value)`.
    *   `type_signature`: The string describing the Solidity type (e.g., `"uint256"`, `"(uint256,address)"`).
    *   `encoded_value`: The actual result, ABI-encoded.
*   **What to do**: Use `env::commit_slice` to send this encoded tuple.

## 📂 Where to modify the code

The main file to modify is:
`methods/guest/src/bin/guest.rs`

You will already find a working example implementing this pattern. You can use it as a base and replace the calculation logic with your own.

## 📦 Useful Dependencies

The template already includes the necessary libraries in `Cargo.toml`:
- `risc0-zkvm`: To interact with the VM (`env::read`, `env::commit`).
- `alloy-sol-types`: For Ethereum-compatible ABI encoding/decoding.
