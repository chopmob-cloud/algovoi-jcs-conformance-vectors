// Generic preimage runner -- Rust / serde_jcs 0.2.0. Usage: cargo run --release --quiet -- <set.json>
use std::env; use std::fs;
use base64::Engine; use base64::engine::general_purpose::STANDARD as B64;
use sha2::{Digest, Sha256};
fn hexs(b: &[u8]) -> String { let mut s = String::with_capacity(b.len()*2); for x in b { s.push_str(&format!("{:02x}", x)); } s }
fn sha256_jcs(val: &serde_json::Value) -> (String, String) {
    let canon = serde_jcs::to_string(val).expect("jcs"); let bytes = canon.as_bytes();
    (B64.encode(bytes), hexs(&Sha256::digest(bytes)))
}
fn main() {
    let args: Vec<String> = env::args().collect();
    let raw = fs::read_to_string(&args[1]).expect("read");
    let data: serde_json::Value = serde_json::from_str(&raw).expect("parse");
    let vectors = data["vectors"].as_array().expect("vectors[]");
    let (mut pass, mut fail) = (0usize, 0usize);
    for v in vectors {
        if v["preimage"].is_null() { continue; }
        let (b64, dg) = sha256_jcs(&v["preimage"]);
        let exp_b64 = v["expected_jcs_bytes_b64"].as_str().unwrap_or("");
        let eh = v["expected_transition_hash"].as_str().or_else(|| v["expected_action_ref"].as_str()).unwrap_or("");
        if b64 == exp_b64 && dg == eh { pass += 1; }
        else { fail += 1; println!("  FAIL {}", v["vector_id"].as_str().unwrap_or("?")); }
    }
    println!("{}/{} PASS", pass, pass + fail);
    if fail > 0 { std::process::exit(1); }
}
