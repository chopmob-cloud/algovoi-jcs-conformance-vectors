// Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE in this directory.
// Retention Chain v1 vector runner -- Rust / serde_jcs 0.2.0
//
// Validates sha256(JCS(preimage)) == expected_chain_ref
//
// Usage:  cargo run --release --quiet -- <vector_set_json>

use std::env;
use std::fs;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use sha2::{Digest, Sha256};

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b { s.push_str(&format!("{:02x}", byte)); }
    s
}

fn sha256_jcs(val: &serde_json::Value) -> (String, String) {
    let canon = serde_jcs::to_string(val).expect("jcs");
    let bytes  = canon.as_bytes();
    let b64    = B64.encode(bytes);
    let hash   = "sha256:".to_owned() + &hex_encode(&Sha256::digest(bytes));
    (b64, hash)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: runner_rust <vector_set_json>");
        std::process::exit(2);
    }
    let raw  = fs::read_to_string(&args[1]).expect("read");
    let data: serde_json::Value = serde_json::from_str(&raw).expect("parse");
    let vectors = data["vectors"].as_array().expect("vectors[]");

    let mut pass = 0usize;
    let mut fail = 0usize;

    for v in vectors {
        let vid = v["vector_id"].as_str().unwrap_or("?");
        let (b64, chain_ref) = sha256_jcs(&v["preimage"]);

        let b64_ok = b64       == v["expected_jcs_bytes_b64"].as_str().unwrap_or("");
        let ref_ok = chain_ref == v["expected_chain_ref"].as_str().unwrap_or("");

        if b64_ok && ref_ok {
            pass += 1;
        } else {
            fail += 1;
            if !b64_ok { println!("  FAIL {} jcs_bytes_b64 mismatch", vid); }
            if !ref_ok  { println!("  FAIL {} chain_ref (got {})", vid, chain_ref); }
        }
    }
    println!("{}/{} PASS", pass, pass + fail);
    if fail > 0 { std::process::exit(1); }
}
