#!/usr/bin/env python3
"""
Benchmark Pipeline for RISC0FLOW Merkle Proofs.

This script runs the full proving pipeline (session, STARK, Groth16, on-chain verify)
for a Merkle tree of a given depth, measuring wall-clock time for each phase via
the `time` command.  Results are collected in metrics/ and proofs/, then moved to
../results/dN/.

Usage:
    python3 benchmark_pipeline.py <depth>

Examples:
    python3 benchmark_pipeline.py 10     # depth 10 (1024 leaves)
    python3 benchmark_pipeline.py 32     # depth 32
"""

import hashlib
import sys
import os
import random
import subprocess
import shutil
import glob


# ============================================================================
# CONSTANTS
# ============================================================================

HOST_BIN = "./target/release/host"
WALLET = "4d71469637941193a58b47867a386ad3a587b0973942cc2b77aef5072ac53b24"
PROOFS_DIR = "proofs"
METRICS_DIR = "metrics"


# ============================================================================
# MERKLE PROOF GENERATION  (same logic as merkle_test.py)
# ============================================================================

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def random_bytes32() -> bytes:
    return random.randbytes(32)


def generate_merkle_proof(depth: int) -> dict:
    if depth < 1:
        raise ValueError("Depth must be at least 1")

    random.seed(depth)
    leaf = random_bytes32()
    siblings = [random_bytes32() for _ in range(depth)]
    directions = [random.choice([True, False]) for _ in range(depth)]

    current = leaf
    for i in range(depth):
        sibling = siblings[i]
        if directions[i]:
            current = sha256(current + sibling)
        else:
            current = sha256(sibling + current)

    return {
        'leaf': leaf,
        'siblings': siblings,
        'directions': directions,
        'root': current,
        'depth': depth,
    }


def format_bytes32(b: bytes) -> str:
    return f"0x{b.hex()}"


def format_directions(directions: list) -> str:
    return '[' + ','.join('r' if d else 'l' for d in directions) + ']'


def format_siblings(siblings: list) -> str:
    return '[' + ','.join(format_bytes32(s) for s in siblings) + ']'


def generate_input_string(proof: dict) -> str:
    return (
        f"<merkle_proof; "
        f"leaf={format_bytes32(proof['leaf'])}, "
        f"siblings={format_siblings(proof['siblings'])}, "
        f"directions={format_directions(proof['directions'])}, "
        f"root={format_bytes32(proof['root'])}>"
    )


# ============================================================================
# HELPERS
# ============================================================================

def write_input_file(proof: dict) -> str:
    """Write input string to a temporary file, return its path."""
    input_str = generate_input_string(proof)
    input_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".merkle_input.tmp")
    with open(input_file, 'w') as f:
        f.write(input_str)
        f.flush()
    return input_file


def clear_directory(path: str):
    """Remove all files in a directory (if it exists)."""
    if os.path.isdir(path):
        for entry in os.listdir(path):
            full = os.path.join(path, entry)
            if os.path.isfile(full):
                os.remove(full)


def find_proof_file(directory: str) -> str:
    """Return the single .bin file in the given directory."""
    bins = glob.glob(os.path.join(directory, "*.bin"))
    if len(bins) == 0:
        raise FileNotFoundError(f"No .bin proof file found in {directory}")
    if len(bins) > 1:
        # pick the most recent one
        bins.sort(key=os.path.getmtime, reverse=True)
    return bins[0]


def run_timed(command: list, time_output_file: str, phase_label: str):
    """
    Run a command prefixed with /usr/bin/time, capturing time's output
    (which goes to stderr) into the specified file.

    The command's own stdout/stderr are printed to the terminal as usual.
    """
    os.makedirs(METRICS_DIR, exist_ok=True)
    time_file_path = os.path.join(METRICS_DIR, time_output_file)

    # Use bash to wrap the command so that `time` stderr is redirected to a file
    # while the command's own stdout/stderr remain visible on the terminal.
    cmd_str = ' '.join(command)
    bash_command = (
        f'{{ time {cmd_str} ; }} 2> >(tee {time_file_path} >&2)'
    )

    print(f"\n{'='*70}")
    print(f"  PHASE: {phase_label}")
    print(f"  CMD:   {cmd_str}")
    print(f"  TIME OUTPUT -> {time_file_path}")
    print(f"{'='*70}\n")

    result = subprocess.run(
        ["bash", "-c", bash_command],
        # stdout and stderr go straight to terminal
    )
    if result.returncode != 0:
        print(f"WARNING: phase '{phase_label}' exited with code {result.returncode}")
    return result.returncode


# ============================================================================
# PIPELINE PHASES
# ============================================================================

def phase_session(input_file: str, depth: int) -> int:
    """Phase 1: Execute session (trace generation) with metrics."""
    command = [
        HOST_BIN, "run",
        "--input-file", input_file,
        "--session",
        "--metrics",
    ]
    return run_timed(command, f"time_session_d{depth}", "SESSION")


def phase_groth16(input_file: str, depth: int) -> int:
    """Phase 2: Generate Groth16 proof with metrics."""
    command = [
        HOST_BIN, "run",
        "--input-file", input_file,
        "--prove", "groth16",
        "--metrics",
    ]
    return run_timed(command, f"time_groth16_d{depth}", "PROVE GROTH16")


def phase_stark(input_file: str, depth: int) -> int:
    """Phase 3: Generate STARK proof with metrics."""
    command = [
        HOST_BIN, "run",
        "--input-file", input_file,
        "--prove", "stark",
        "--metrics",
    ]
    return run_timed(command, f"time_stark_d{depth}", "PROVE STARK")


def phase_verify(depth: int) -> int:
    """Phase 4: On-chain verification (Sepolia) from proof file."""
    proof_file = find_proof_file(PROOFS_DIR)
    command = [
        HOST_BIN, "run",
        "--verify", "onchain",
        "--network", "sepolia",
        "--source", "file",
        "--proof-file", proof_file,
        "--wallet", WALLET,
        "--n-runs", "15",
        "--metrics",
    ]
    return run_timed(command, f"time_verify_d{depth}", "VERIFY ON-CHAIN (SEPOLIA)")


# ============================================================================
# RESULTS COLLECTION
# ============================================================================

def collect_results(depth: int):
    """Move metrics/ and proofs/ contents to results/dN/."""
    dest = os.path.join("results", f"d{depth}")
    dest_metrics = os.path.join(dest, "metrics")
    dest_proofs = os.path.join(dest, "proofs")

    os.makedirs(dest_metrics, exist_ok=True)
    os.makedirs(dest_proofs, exist_ok=True)

    # Move metrics files
    if os.path.isdir(METRICS_DIR):
        for entry in os.listdir(METRICS_DIR):
            src = os.path.join(METRICS_DIR, entry)
            if os.path.isfile(src):
                shutil.move(src, os.path.join(dest_metrics, entry))

    # Move proof files
    if os.path.isdir(PROOFS_DIR):
        for entry in os.listdir(PROOFS_DIR):
            src = os.path.join(PROOFS_DIR, entry)
            if os.path.isfile(src):
                shutil.move(src, os.path.join(dest_proofs, entry))

    print(f"\nAll results moved to {os.path.abspath(dest)}")


# ============================================================================
# MAIN
# ============================================================================

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 benchmark_pipeline.py <depth>")
        sys.exit(1)

    try:
        depth = int(sys.argv[1])
        if depth < 1:
            print("Error: depth must be >= 1")
            sys.exit(1)
    except ValueError:
        print(f"Error: '{sys.argv[1]}' is not a valid integer")
        sys.exit(1)

    print(f"Benchmark pipeline – Merkle tree depth = {depth}  (2^{depth} = {2**depth} leaves)")

    # Clean proofs dir so phase_verify finds only the right file
    clear_directory(PROOFS_DIR)

    # Generate Merkle proof and write input file
    proof = generate_merkle_proof(depth)
    input_file = write_input_file(proof)

    try:
        # Phase 1 – Session
        phase_session(input_file, depth)

        # Phase 2 – Groth16 proof
        phase_groth16(input_file, depth)

        # Phase 3 – On-chain verify (uses the groth16 proof in proofs/)
        phase_verify(depth)

        # Phase 4 – STARK proof
        phase_stark(input_file, depth)

    finally:
        # Cleanup temp input file
        if os.path.exists(input_file):
            os.remove(input_file)

    # Collect everything into ../results/dN/
    collect_results(depth)

    print("\nDone.")


if __name__ == "__main__":
    main()
