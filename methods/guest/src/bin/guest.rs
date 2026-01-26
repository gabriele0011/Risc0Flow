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

// #![no_main]

// zkVM Guest Program for Merkle Proof of Membership Verification
//
// This program is executed inside the RISC Zero zkVM.
// Its function is to verify the membership of a leaf hash in a Merkle tree,
// given a known root.
//
// The logical process is as follows:
// 1. It receives as private input the leaf, the proof path (a set of sibling nodes),
//    and the corresponding directions.
// 2. It receives as the expected public input the root of the Merkle tree.
// 3. It iteratively recalculates the root starting from the leaf and applying the hashes
//    of the sibling nodes according to the provided directions.
// 4. It asserts that the calculated root is identical to the expected root.
//
// The generation of a valid ZK proof is conditional on the success of this assertion,
// thus ensuring the integrity of the verification without exposing the proof path data.

use alloy_primitives::FixedBytes;
use alloy_sol_types::SolValue;
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::Impl as Sha256;
use risc0_zkvm::sha::Sha256 as Sha256Trait;
use std::io::Read;

// ============================================================================
// HASH PAIR
// ============================================================================

/// Hashes a pair of Merkle tree nodes.
/// 
/// Calculates the SHA-256 hash of two concatenated nodes. The order of concatenation is
/// determined by the `direction` parameter, which specifies the position of the sibling node
/// relative to the current node in the calculation.
///
/// - `direction = false` (left): Indicates that `sibling` is a left sibling.
///   The concatenation is `hash(sibling | current)`.
/// - `direction = true` (right): Indicates that `sibling` is a right sibling.
///   The concatenation is `hash(current | sibling)`.
///
/// This process is fundamental for ascending the tree towards the root.
fn hash_pair(current: &[u8; 32], sibling: &[u8; 32], direction: bool) -> [u8; 32] {
    // Allocate a 64-byte buffer for the concatenation of the two hashes.
    let mut data = [0u8; 64];
    
    if direction {
        // `sibling` is on the right. Concatenation order: [current][sibling].
        data[..32].copy_from_slice(current);
        data[32..].copy_from_slice(sibling);
    } else {
        // `sibling` is on the left. Concatenation order: [sibling][current].
        data[..32].copy_from_slice(sibling);
        data[32..].copy_from_slice(current);
    }
    
    // Calculate the SHA-256 hash of the concatenated buffer using the zkVM's hardware-accelerated implementation.
    let digest = Sha256::hash_bytes(&data);
    
    // Convert the resulting `Digest` type into a `[u8; 32]` byte array.
    digest.as_bytes().try_into().expect("SHA-256 digest should be 32 bytes")
}

// ============================================================================
// COMPUTE MERKLE ROOT
// ============================================================================

/// Reconstructs the Merkle tree root.
/// 
/// Starting from a leaf hash, this function calculates the tree root by iteratively applying
/// the `hash_pair` function for each level, using the sibling nodes and directions
/// provided in the proof path.
///
/// - `leaf`: The starting leaf node hash.
/// - `siblings`: A vector of `[u8; 32]` hashes that constitutes the proof path.
/// - `directions`: A vector of booleans specifying the position (left/right) of each `sibling`.
fn compute_merkle_root(
    leaf: &[u8; 32],
    siblings: &[[u8; 32]],
    directions: &[bool],
) -> [u8; 32] {
    // Initialize the current hash with the leaf's hash.
    let mut current_hash = *leaf;
    
    // Iterate over the proof path, combining the current hash with its sibling at each level.
    for (sibling, &direction) in siblings.iter().zip(directions.iter()) {
        // Update the current hash with the result of the hashing at the upper level.
        current_hash = hash_pair(&current_hash, sibling, direction);
    }
    
    // The resulting hash after the last iteration is the calculated root.
    current_hash
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

/// Entry point of the guest program.
fn main() {
    // 1. Read Input
    // Reads the raw data provided by the host via the zkVM's standard input.
    let mut input_bytes = Vec::<u8>::new();
    env::stdin().read_to_end(&mut input_bytes).unwrap();

    // 2. Decode Input
    // Parses the input bytes according to Solidity's ABI specifications.
    // The expected format is a tuple: (bytes32 leaf, bytes32[] siblings, bool[] directions, bytes32 expected_root).
    let decoded: (FixedBytes<32>, Vec<FixedBytes<32>>, Vec<bool>, FixedBytes<32>) = 
        <(FixedBytes<32>, Vec<FixedBytes<32>>, Vec<bool>, FixedBytes<32>)>::abi_decode(&input_bytes)
            .expect("Input does not conform to the ABI format for merkle_proof");

    let (leaf_fb, siblings_fb, directions, expected_root_fb) = decoded;

    // Convert `FixedBytes` types from `alloy` to native Rust `[u8; 32]` arrays.
    let leaf: [u8; 32] = leaf_fb.into();
    let expected_root: [u8; 32] = expected_root_fb.into();
    let siblings: Vec<[u8; 32]> = siblings_fb.iter().map(|s| (*s).into()).collect();

    // 3. Input Consistency Validation
    // Verifies that the `siblings` and `directions` vectors have the same size.
    assert_eq!(
        siblings.len(), 
        directions.len(), 
        "Dimensional inconsistency between 'siblings' and 'directions'."
    );

    // 4. Execute Calculation Logic
    // Calculates the Merkle tree root based on the input data.
    let computed_root = compute_merkle_root(&leaf, &siblings, &directions);

    // 5. Correspondence Assertion
    // Compares the calculated root with the expected root.
    // This is the critical operation that determines the validity of the proof.
    // If the assertion fails, the guest execution terminates with a `panic`,
    // preventing the generation of a ZK proof.
    assert_eq!(
        computed_root, 
        expected_root, 
        "Verification failed: the calculated root does not match the expected root."
    );

    // 6. Commit Public Output (Journal)
    // If the assertion is successful, the result of the calculation is written to the journal.
    // The journal is a public output of the zkVM, whose content is cryptographically
    // linked to the generated ZK proof.
    // Format: (type string, ABI-encoded data).
    let type_info = "bytes32";
    let root_fb = FixedBytes::<32>::from(computed_root);
    let raw_data = root_fb.abi_encode();
    let journal = (type_info, raw_data).abi_encode();
    
    // Writes the serialized journal to the zkVM's output.
    env::commit_slice(&journal);
}