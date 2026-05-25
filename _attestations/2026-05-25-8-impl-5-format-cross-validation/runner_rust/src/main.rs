// Generic vector-set runner (Rust / serde_jcs 0.2.0).
//
// Usage:  cargo run --release --quiet -- <vector_set_json>

use std::env;
use std::fs;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use sha2::{Digest, Sha256};

fn main() {
    let args: Vec<String> = env::args().collect();
    let path = &args[1];
    let raw = fs::read_to_string(path).expect("read");
    let data: serde_json::Value = serde_json::from_str(&raw).expect("parse");
    let vectors = data["vectors"].as_array().expect("vectors[]");

    let mut pass = 0;
    let mut fail = 0;

    for v in vectors {
        let payload = v.get("receipt").or_else(|| v.get("response")).or_else(|| v.get("row"));
        let Some(payload) = payload else { continue };

        let canon = serde_jcs::to_string(payload).expect("jcs");
        let canon_bytes = canon.as_bytes();
        let b64 = B64.encode(canon_bytes);
        let digest_bytes = Sha256::digest(canon_bytes);
        let digest = hex_encode(&digest_bytes);

        let expected_hash = v.get("expected_content_hash")
            .or_else(|| v.get("expected_row_content_hash"))
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let expected_b64 = v["expected_jcs_bytes_b64"].as_str().unwrap_or("");

        if b64 == expected_b64 && digest == expected_hash {
            pass += 1;
        } else {
            fail += 1;
            println!("  FAIL {}", v["vector_id"].as_str().unwrap_or("?"));
        }
    }
    println!("{}/{} PASS", pass, pass + fail);
    if fail > 0 {
        std::process::exit(1);
    }
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}
