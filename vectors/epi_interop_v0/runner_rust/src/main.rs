// epi_interop_v0 runner -- Rust / serde_jcs 0.2.0
//
// Validates sha256(JCS(input)) == frame_id for each vector
//
// Usage (from epi_interop_v0/):
//   cargo +stable-x86_64-pc-windows-gnu run --release --quiet

use std::fs;
use std::path::Path;

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
    let manifest = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let vec_file = src_dir.join("../epi_interop_v0.json");
    let _ = manifest;

    let raw  = fs::read_to_string(&vec_file).expect("read epi_interop_v0.json");
    let data: serde_json::Value = serde_json::from_str(&raw).expect("parse");
    let vectors = data["vectors"].as_array().expect("vectors[]");

    let mut pass = 0usize;
    let mut fail = 0usize;

    for v in vectors {
        let id = v["id"].as_str().unwrap_or("?");
        let (b64, frame_id) = sha256_jcs(&v["input"]);

        let b64_ok = b64      == v["expected_jcs_bytes_b64"].as_str().unwrap_or("");
        let ref_ok = frame_id == v["frame_id"].as_str().unwrap_or("");

        if b64_ok && ref_ok {
            pass += 1;
        } else {
            fail += 1;
            if !b64_ok { println!("  FAIL {} jcs_bytes_b64 mismatch", id); }
            if !ref_ok  { println!("  FAIL {} frame_id (got {})", id, frame_id); }
        }
    }
    println!("{}/{} PASS", pass, pass + fail);
    if fail > 0 { std::process::exit(1); }
}
