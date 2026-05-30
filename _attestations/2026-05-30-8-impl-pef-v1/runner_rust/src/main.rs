// PEF v1 vector runner -- Rust / serde_jcs 0.2.0
//
// Validates sha256(JCS(receipt)) == expected_receipt_hash and
//           sha256(JCS(preimage)) == expected_frame_id
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
    let raw  = fs::read_to_string(&args[1]).expect("read");
    let data: serde_json::Value = serde_json::from_str(&raw).expect("parse");
    let vectors = data["vectors"].as_array().expect("vectors[]");

    let mut pass = 0usize;
    let mut fail = 0usize;

    for v in vectors {
        let (r_b64, r_hash) = sha256_jcs(&v["receipt"]);
        let (p_b64, p_hash) = sha256_jcs(&v["preimage"]);

        let receipt_ok  = r_b64 == v["expected_receipt_jcs_bytes_b64"].as_str().unwrap_or("")
                       && r_hash == v["expected_receipt_hash"].as_str().unwrap_or("");
        let preimage_ok = p_b64 == v["expected_preimage_jcs_bytes_b64"].as_str().unwrap_or("")
                       && p_hash == v["expected_frame_id"].as_str().unwrap_or("");

        if receipt_ok && preimage_ok {
            pass += 1;
        } else {
            fail += 1;
            let vid = v["vector_id"].as_str().unwrap_or("?");
            if !receipt_ok  { println!("  FAIL {} receipt_hash", vid); }
            if !preimage_ok { println!("  FAIL {} frame_id (got {})", vid, p_hash); }
        }
    }
    println!("{}/{} PASS", pass, pass + fail);
    if fail > 0 { std::process::exit(1); }
}
