#!/usr/bin/env python3
"""
Generatore di Merkle Proof per testing RISC0FLOW.

Uso:
    python3 merkle_test_generator.py [profondità]
    
Esempi:
    python3 merkle_test_generator.py        # profondità 3 (default)
    python3 merkle_test_generator.py 5      # profondità 5
    python3 merkle_test_generator.py 10     # profondità 10
"""

import hashlib
import secrets
import sys
import random

def sha256(data: bytes) -> bytes:
    """Calcola SHA-256 di data."""
    return hashlib.sha256(data).digest()

def random_bytes32() -> bytes:
    """Genera 32 bytes casuali."""
    return secrets.token_bytes(32)

def generate_merkle_proof(depth: int) -> dict:
    """
    Genera un Merkle proof casuale di profondità specificata.
    
    Args:
        depth: Numero di livelli dell'albero (= numero di siblings)
    
    Returns:
        dict con leaf, siblings, directions, root
    """
    if depth < 1:
        raise ValueError("La profondità deve essere almeno 1")
    
    # Genera foglia casuale (già hashata)
    leaf = random_bytes32()
    
    # Genera siblings casuali
    siblings = [random_bytes32() for _ in range(depth)]
    
    # Genera directions casuali: False = left (sibling a sinistra), True = right (sibling a destra)
    directions = [random.choice([True, False]) for _ in range(depth)]
    
    # Calcola la root
    current = leaf
    for i in range(depth):
        sibling = siblings[i]
        if directions[i]:
            # sibling a destra: hash(current || sibling)
            current = sha256(current + sibling)
        else:
            # sibling a sinistra: hash(sibling || current)
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
    """Formatta bytes come 0x..."""
    return f"0x{b.hex()}"

def format_directions(directions: list) -> str:
    """Formatta directions come [l,r,l,...]"""
    return '[' + ','.join('r' if d else 'l' for d in directions) + ']'

def format_siblings(siblings: list) -> str:
    """Formatta siblings come [0x...,0x...,...]"""
    return '[' + ','.join(format_bytes32(s) for s in siblings) + ']'

def print_proof(proof: dict):
    """Stampa il proof in formato leggibile."""
    print(f"\n{'='*60}")
    print(f"MERKLE PROOF (profondità: {proof['depth']})")
    print(f"{'='*60}")
    print(f"\nleaf={format_bytes32(proof['leaf'])}")
    print(f"\nsiblings={format_siblings(proof['siblings'])}")
    print(f"\ndirections={format_directions(proof['directions'])}")
    print(f"\nroot={format_bytes32(proof['root'])}")

def generate_cargo_command(proof: dict, mode: str = "session") -> str:
    """
    Genera il comando cargo run completo.
    
    Args:
        proof: Il Merkle proof generato
        mode: "session", "stark", "groth16", "verify-stark", "verify-groth16"
    """
    input_str = (
        f"<merkle_proof; "
        f"leaf={format_bytes32(proof['leaf'])}, "
        f"siblings={format_siblings(proof['siblings'])}, "
        f"directions={format_directions(proof['directions'])}, "
        f"root={format_bytes32(proof['root'])}>"
    )
    
    if mode == "session":
        return f"cargo run --bin host -- run --session --input '{input_str}' --metrics"
    elif mode == "stark":
        return f"cargo run --bin host -- run --prove stark --input '{input_str}' --metrics"
    elif mode == "groth16":
        return f"cargo run --bin host -- run --prove groth16 --input '{input_str}' --metrics"
    elif mode == "verify-stark":
        return f"cargo run --bin host -- run --prove stark --source new --verify offchain --input '{input_str}' --metrics"
    elif mode == "verify-groth16":
        return f"cargo run --bin host -- run --prove groth16 --source new --verify offchain --input '{input_str}' --metrics"
    else:
        raise ValueError(f"Modo sconosciuto: {mode}")

def main():
    # Default: profondità 3
    depth = 3
    
    if len(sys.argv) > 1:
        try:
            depth = int(sys.argv[1])
            if depth < 1:
                print("Errore: la profondità deve essere >= 1")
                sys.exit(1)
        except ValueError:
            print(f"Errore: '{sys.argv[1]}' non è un numero valido")
            print(__doc__)
            sys.exit(1)
    
    # Genera il proof
    proof = generate_merkle_proof(depth)
    
    # Stampa il proof
    print_proof(proof)
    
    # Stampa i comandi
    print(f"\n{'='*60}")
    print("COMANDI CARGO RUN")
    print(f"{'='*60}")
    
    print("\n# Solo sessione (veloce, no proving):")
    print(generate_cargo_command(proof, "session"))
    
    print("\n# Genera prova STARK:")
    print(generate_cargo_command(proof, "stark"))
    
    print("\n# Genera prova STARK + verifica offchain:")
    print(generate_cargo_command(proof, "verify-stark"))
    
    print("\n# Genera prova Groth16 (per verifica on-chain):")
    print(generate_cargo_command(proof, "groth16"))
    
    print()

if __name__ == "__main__":
    main()
