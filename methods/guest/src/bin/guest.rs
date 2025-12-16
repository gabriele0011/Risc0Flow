use alloy_primitives::U256;
use alloy_sol_types::SolValue;
use num_bigint::{BigUint, ToBigUint};
use risc0_zkvm::guest::env;
use std::io::Read;
use std::str::FromStr;

/// Calcola (base^exponent) usando un semplice ciclo di moltiplicazione (inefficiente).
fn power(base: &BigUint, exp: &BigUint) -> BigUint {
    let mut res = 1u32.to_biguint().unwrap();
    let mut i = 0u32.to_biguint().unwrap();
    let one = 1u32.to_biguint().unwrap();

    while i < *exp {
        res *= base;
        i += &one;
    }
    res
}

/// Calcola (base^exponent) % modulus in modo non efficiente e restituisce un U256.
fn mod_pow(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> U256 {

    // 1. Calcola direttamente la potenza b^e usando la nostra funzione inefficiente.
    let power_result = power(base, exponent);

    // 2. Calcola il modulo sul risultato.
    let final_result_biguint = power_result % modulus;

    // Converte il BigUint risultante in un U256.
    let result = U256::from_str(&final_result_biguint.to_string()).unwrap();
    result
}


fn main() {
    // Leggi i dati di input come bytes ABI-encoded
    let mut input_bytes = Vec::<u8>::new();
    env::stdin().read_to_end(&mut input_bytes).unwrap();

    // Decodifica 3 uint256 ABI-encoded
    let (b, e, m): (U256, U256, U256) = <(U256, U256, U256)>::abi_decode(&input_bytes)
        .expect("Input non è una tupla ABI-encoded di 3 uint256");

    // Converti in BigUint
    let b = BigUint::from_bytes_be(&b.to_be_bytes::<32>());
    let e = BigUint::from_bytes_be(&e.to_be_bytes::<32>());
    let m = BigUint::from_bytes_be(&m.to_be_bytes::<32>());

    // Esegui l'esponenziazione modulare standard
    let result = mod_pow(&b, &e, &m);

    // Emette direttamente: (type_string, raw_data)
    let type_info = "uint256";
    let raw_data = result.abi_encode();
    let journal = (type_info, raw_data).abi_encode();
    env::commit_slice(&journal);
}
