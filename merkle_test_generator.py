#!/usr/bin/env python3
"""
Merkle Proof Generator for RISC0FLOW Testing.

This script generates valid Merkle proofs with random data for testing the
RISC0FLOW zkVM proving pipeline. It creates a complete proof specification
and outputs ready-to-use cargo commands.

Usage:
    python3 merkle_test_generator.py [depth]
    
Examples:
    python3 merkle_test_generator.py        # depth 3 (default, 8 leaves)
    python3 merkle_test_generator.py 5      # depth 5 (32 leaves)
    python3 merkle_test_generator.py 10     # depth 10 (1024 leaves)

Note:
    Tree depth determines the number of siblings in the proof path.
    A tree of depth N can hold 2^N leaves.
"""

import hashlib
import secrets
import sys
import random
import subprocess


def sha256(data: bytes) -> bytes:
    """
    Compute SHA-256 hash of input data.
    
    Args:
        data: Raw bytes to hash.
        
    Returns:
        32-byte SHA-256 digest.
    """
    return hashlib.sha256(data).digest()


def random_bytes32() -> bytes:
    """
    Generate 32 cryptographically secure random bytes.
    
    Returns:
        32-byte random value (suitable for use as hash).
    """
    return secrets.token_bytes(32)

def generate_merkle_proof(depth: int) -> dict:
    """
    Generate a random but valid Merkle proof of the specified depth.
    
    This function creates a complete Merkle proof by:
    1. Generating a random leaf hash.
    2. Generating random sibling hashes for each tree level.
    3. Randomly assigning left/right positions for each sibling.
    4. Computing the root by traversing up the tree.
    
    The resulting proof is guaranteed to be valid (the guest will verify it).
    
    Args:
        depth: Number of levels in the tree (= number of siblings in the proof).
               Must be >= 1.
    
    Returns:
        Dictionary containing:
            - leaf: 32-byte leaf hash
            - siblings: List of 32-byte sibling hashes
            - directions: List of booleans (True = sibling on right)
            - root: 32-byte computed root hash
            - depth: The tree depth
    
    Raises:
        ValueError: If depth < 1.
    """
    if depth < 1:
        raise ValueError("Depth must be at least 1")
    
    # Generate random leaf (pre-hashed, as expected by the guest)
    leaf = random_bytes32()
    
    # Generate random siblings for each level of the tree
    siblings = [random_bytes32() for _ in range(depth)]
    
    # Generate random directions for each sibling:
    #   - False (left): sibling is on the left  -> hash(sibling || current)
    #   - True (right): sibling is on the right -> hash(current || sibling)
    directions = [random.choice([True, False]) for _ in range(depth)]
    
    # Compute the root by traversing from leaf to root
    current = leaf
    for i in range(depth):
        sibling = siblings[i]
        if directions[i]:
            # Sibling is on the right: current node is left child
            # Concatenation order: [current][sibling]
            current = sha256(current + sibling)
        else:
            # Sibling is on the left: current node is right child
            # Concatenation order: [sibling][current]
            current = sha256(sibling + current)
    
    root = current
    
    return {
        'leaf': leaf,
        'siblings': siblings,
        'directions': directions,
        'root': root,
        'depth': depth
    }

def format_bytes32(b: bytes) -> str:
    """
    Format 32-byte value as hex string with 0x prefix.
    
    Args:
        b: 32-byte value.
        
    Returns:
        Hex string like "0x1a2b3c...".
    """
    return f"0x{b.hex()}"


def format_directions(directions: list) -> str:
    """
    Format directions list for CLI input.
    
    Args:
        directions: List of booleans.
        
    Returns:
        String like "[l,r,l,r]" where l=left, r=right.
    """
    return '[' + ','.join('r' if d else 'l' for d in directions) + ']'


def format_siblings(siblings: list) -> str:
    """
    Format siblings list for CLI input.
    
    Args:
        siblings: List of 32-byte hashes.
        
    Returns:
        String like "[0x...,0x...,0x...]".
    """
    return '[' + ','.join(format_bytes32(s) for s in siblings) + ']'


def print_proof(proof: dict):
    """
    Print the Merkle proof in a human-readable format.
    
    Args:
        proof: Dictionary containing the proof data.
    """
    pass  # Output minimizzato: nessuna stampa

def generate_input_string(proof: dict) -> str:
    """
    Generate the input string for the host CLI.
    
    Args:
        proof: The generated Merkle proof.
    
    Returns:
        Input string in the format expected by the host CLI.
    """
    return (
        f"<merkle_proof; "
        f"leaf={format_bytes32(proof['leaf'])}, "
        f"siblings={format_siblings(proof['siblings'])}, "
        f"directions={format_directions(proof['directions'])}, "
        f"root={format_bytes32(proof['root'])}>"
    )


def generate_cargo_command(proof: dict, input_file: str) -> list:
    """
    Generate a cargo run command for Groth16 proving with metrics.
    
    Args:
        proof: The generated Merkle proof.
        input_file: Path to the temporary file containing the input string.
    
    Returns:
        List of command arguments.
    """
    return [
        "./target/release/host",
        "run",
        "--prove", "groth16",
        "--input-file", input_file,
        "--verify", "onchain",
        "--network", "sepolia",
        "--source", "new",
        "--n-runs", "1",
        "--wallet", "4d71469637941193a58b47867a386ad3a587b0973942cc2b77aef5072ac53b24",
        "--metrics"
    ]


def format_cargo_command(input_file: str) -> str:
    """
    Format the cargo command as a string for display purposes.
    
    Args:
        input_file: Path to the input file.
    
    Returns:
        Human-readable command string.
    """
    return f"./target/release/host run --prove groth16 --input-file '{input_file}' verify sepolia --wallet 4d71469637941193a58b47867a386ad3a587b0973942cc2b77aef5072ac53b24 --metrics"

def main():
    """
    Main entry point.
    
    Parses command-line arguments, generates a Merkle proof,
    and prints a ready-to-use cargo command for Groth16 proving.
    """
    # Default depth: 3 levels (tree with 8 leaves)
    depth = 3
    
    # Parse optional depth argument
    if len(sys.argv) > 1:
        try:
            depth = int(sys.argv[1])
            if depth < 1:
                print("Error: depth must be >= 1")
                sys.exit(1)
        except ValueError:
            print(f"Error: '{sys.argv[1]}' is not a valid number")
            print(__doc__)
            sys.exit(1)
    
    # Generate the proof
    proof = generate_merkle_proof(depth)
    
    # Output minimizzato: nessuna stampa della proof
    
    # Write input to a temporary file to avoid argument length limits
    import tempfile
    import os

    input_str = generate_input_string(proof)

    # Create a temporary file in the current directory for the input
    input_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".merkle_input.tmp")
    with open(input_file, 'w') as f:
        f.write(input_str)
        f.flush()  # Ensure data is written to disk

    # Esegui il comando host in modalità asincrona, senza attendere la fine
    import subprocess
    command = generate_cargo_command(proof, input_file)
    subprocess.run(command)
    # La pulizia del file temporaneo è ora manuale


if __name__ == "__main__":
    main()
