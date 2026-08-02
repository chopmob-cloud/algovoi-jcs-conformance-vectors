// Differential adversarial substrate -- Rust canon probe (serde_jcs 0.2.0).
// Contract: see probe_python.py. Emits "<id>\t h:<hex> | R:<reason>" per case.
use std::env;
use std::fs;
use sha2::{Digest, Sha256};
use serde_json::Value;

fn verdict(raw: &str) -> String {
    let val: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return "R:parse".to_string(),
    };
    match serde_jcs::to_string(&val) {
        Ok(canon) => {
            let mut h = Sha256::new();
            h.update(canon.as_bytes());
            let hexs: String = h.finalize().iter().map(|b| format!("{:02x}", b)).collect();
            format!("h:{}", hexs)
        }
        Err(_) => "R:canon".to_string(),
    }
}

fn main() {
    let path = env::args().nth(1).expect("cases path");
    let d: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let mut out = String::new();
    for c in d["cases"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        let raw = c["raw"].as_str().unwrap();
        out.push_str(&format!("{}\t{}\n", id, verdict(raw)));
    }
    print!("{}", out);
}
