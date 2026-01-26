// Merkle Tree Proof of Membership - Guest Code
// 
// Questo guest verifica l'appartenenza di una foglia a un Merkle tree.
// Input (privati): leaf, siblings[], directions[]
// Input (pubblico tramite confronto): expected_root
// Output (pubblico nel journal): computed_root (bytes32)

use alloy_primitives::FixedBytes;
use alloy_sol_types::SolValue;
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::Impl as Sha256;
use risc0_zkvm::sha::Sha256 as Sha256Trait;
use std::io::Read;

/// Calcola SHA-256 di due hash concatenati
/// L'ordine dipende dalla direction:
/// - direction = false (left): hash(sibling || current)
/// - direction = true (right): hash(current || sibling)
fn hash_pair(current: &[u8; 32], sibling: &[u8; 32], direction: bool) -> [u8; 32] {
    let mut data = [0u8; 64];
    
    if direction {
        // sibling a destra: current || sibling
        data[..32].copy_from_slice(current);
        data[32..].copy_from_slice(sibling);
    } else {
        // sibling a sinistra: sibling || current
        data[..32].copy_from_slice(sibling);
        data[32..].copy_from_slice(current);
    }
    
    // Usa SHA-256 nativo di RISC0
    let digest = Sha256::hash_bytes(&data);
    // Converti Digest in [u8; 32]
    digest.as_bytes().try_into().expect("SHA-256 digest should be 32 bytes")
}

/// Calcola la root del Merkle tree partendo dalla foglia e dal proof path
fn compute_merkle_root(
    leaf: &[u8; 32],
    siblings: &[[u8; 32]],
    directions: &[bool],
) -> [u8; 32] {
    let mut current = *leaf;
    
    for (sibling, &direction) in siblings.iter().zip(directions.iter()) {
        current = hash_pair(&current, sibling, direction);
    }
    
    current
}

fn main() {
    // Leggi i dati di input come bytes ABI-encoded
    let mut input_bytes = Vec::<u8>::new();
    env::stdin().read_to_end(&mut input_bytes).unwrap();

    // Decodifica: (bytes32 leaf, bytes32[] siblings, bool[] directions, bytes32 expected_root)
    let decoded: (FixedBytes<32>, Vec<FixedBytes<32>>, Vec<bool>, FixedBytes<32>) = 
        <(FixedBytes<32>, Vec<FixedBytes<32>>, Vec<bool>, FixedBytes<32>)>::abi_decode(&input_bytes)
            .expect("Input non è una tupla ABI-encoded valida per merkle_proof");

    let (leaf_fb, siblings_fb, directions, expected_root_fb) = decoded;

    // Converti da FixedBytes a array [u8; 32]
    let leaf: [u8; 32] = leaf_fb.into();
    let expected_root: [u8; 32] = expected_root_fb.into();
    let siblings: Vec<[u8; 32]> = siblings_fb.iter().map(|s| (*s).into()).collect();

    // Verifica consistenza (già validato dall'host, ma doppio check)
    assert_eq!(
        siblings.len(), 
        directions.len(), 
        "siblings e directions devono avere la stessa lunghezza"
    );

    // Calcola la root partendo dalla foglia
    let computed_root = compute_merkle_root(&leaf, &siblings, &directions);

    // Verifica che la root calcolata corrisponda a quella attesa
    assert_eq!(
        computed_root, 
        expected_root, 
        "Merkle proof non valido: root calcolata non corrisponde"
    );

    // Commit della root calcolata nel journal (output pubblico)
    // Formato: (string type_signature, bytes encoded_value)
    let type_info = "bytes32";
    let root_fb = FixedBytes::<32>::from(computed_root);
    let raw_data = root_fb.abi_encode();
    let journal = (type_info, raw_data).abi_encode();
    env::commit_slice(&journal);
}
