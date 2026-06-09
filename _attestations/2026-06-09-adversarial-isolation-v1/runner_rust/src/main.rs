// Generic input runner (Rust / serde_jcs 0.2.0). Claim 1 (input bytes) only.
// Usage: cargo run --release --quiet -- <set.json>
use std::env;
use std::fs;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use sha2::{Digest, Sha256};

fn hexs(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let data: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&args[1]).unwrap()).unwrap();
    let (mut p, mut q) = (0usize, 0usize);
    for v in data["vectors"].as_array().unwrap() {
        if v["input"].is_null() {
            continue;
        }
        let canon = serde_jcs::to_string(&v["input"]).expect("jcs");
        let bytes = canon.as_bytes();
        let b64 = B64.encode(bytes);
        let dg = hexs(&Sha256::digest(bytes));
        if b64 == v["input_jcs_bytes_b64"].as_str().unwrap_or("")
            && dg == v["input_content_sha256"].as_str().unwrap_or("")
        {
            p += 1;
        } else {
            q += 1;
            println!("  FAIL {}", v["vector_id"].as_str().unwrap_or("?"));
        }
    }
    println!("{}/{} PASS", p, p + q);
    if q > 0 {
        std::process::exit(1);
    }
}
