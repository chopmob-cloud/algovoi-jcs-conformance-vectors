// runner_rust -- RFC 9421 + RFC 9530 cross-validation runner for the
// rfc9421_proxy_chain_v0 fixture.
//
// Run from the parent directory containing request.fixture.json:
//   cd runner_rust && cargo run --release

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

fn parse_signature_input(value: &str) -> (Vec<String>, std::collections::HashMap<String, String>) {
    // Handle both labelled `sig=(...)` and unlabelled `(...)` forms
    let body = if let Some(idx) = value.find("=(") {
        &value[idx + 1..]
    } else {
        value
    };
    let close = body.find(')').unwrap();
    let inside = &body[1..close];
    let params = body[close + 1..].trim_start_matches(';');

    let re = Regex::new(r#""([^"]+)""#).unwrap();
    let covered: Vec<String> = re
        .captures_iter(inside)
        .map(|c| c[1].to_string())
        .collect();

    let mut param_map = std::collections::HashMap::new();
    for kv in params.split(';') {
        let kv = kv.trim();
        if kv.is_empty() {
            continue;
        }
        if let Some((k, v)) = kv.split_once('=') {
            param_map.insert(k.to_string(), v.trim_matches('"').to_string());
        }
    }
    (covered, param_map)
}

fn parse_signature_value(value: &str) -> Vec<u8> {
    let body = if let Some(idx) = value.find("=:") {
        &value[idx + 2..]
    } else {
        value.trim_start_matches(':')
    };
    let body = body.trim_end_matches(':');
    base64::engine::general_purpose::STANDARD.decode(body).unwrap()
}

fn main() {
    let fixture_path = PathBuf::from("../request.fixture.json");
    let data = fs::read_to_string(&fixture_path).expect("read fixture");
    let fix: Value = serde_json::from_str(&data).expect("parse JSON");

    let headers = &fix["request"]["headers"];
    let si_header = headers["signature-input"].as_str().unwrap();
    let sig_header = headers["signature"].as_str().unwrap();
    let cd_header = headers["content-digest"].as_str().unwrap();

    let (covered, params) = parse_signature_input(si_header);

    let method = fix["request"]["method"].as_str().unwrap().to_string(); // rfc9421: preserve case
    let authority = fix["request"]["authority"].as_str().unwrap().to_lowercase();
    let path = fix["request"]["path"].as_str().unwrap();

    let mut lines = Vec::new();
    for name in &covered {
        let val = match name.as_str() {
            "@method" => method.clone(),
            "@authority" => authority.clone(),
            "@path" => path.to_string(),
            "content-digest" => cd_header.to_string(),
            other => headers[other].as_str().unwrap().to_string(),
        };
        lines.push(format!("\"{}\": {}", name, val));
    }
    // RFC 9421 §2.5: trailing @signature-params line (post-label portion of Signature-Input).
    let params_raw = &si_header[si_header.find('=').unwrap() + 1..];
    lines.push(format!("\"@signature-params\": {}", params_raw));
    let _ = &params;
    let signing_base = lines.join("\n");

    let expected_base = fix["signing"]["signing_base"].as_str().unwrap();
    if signing_base != expected_base {
        println!("[FAIL] signing base mismatch");
        println!("  expected: {:?}", expected_base);
        println!("  got:      {:?}", signing_base);
        std::process::exit(1);
    }
    println!("[OK] signing base byte-identical to fixture");

    let digest = Sha256::digest(b"");
    let expected_cd = format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(digest)
    );
    if expected_cd != cd_header {
        println!("[FAIL] content-digest mismatch");
        std::process::exit(1);
    }
    println!("[OK] RFC 9530 content-digest verified");

    let pub_hex = fix["keypair"]["public_key_hex"].as_str().unwrap();
    let pub_bytes: [u8; 32] = hex::decode(pub_hex).unwrap().try_into().unwrap();
    let verifying_key = VerifyingKey::from_bytes(&pub_bytes).expect("pubkey");
    let sig_bytes = parse_signature_value(sig_header);
    let sig_arr: [u8; 64] = sig_bytes.try_into().expect("64-byte sig");
    let signature = Signature::from_bytes(&sig_arr);

    match verifying_key.verify(signing_base.as_bytes(), &signature) {
        Ok(_) => {
            println!("[OK] Ed25519 signature verified");
            println!("PASS (Rust: ed25519-dalek 2 + sha2 0.10)");
        }
        Err(e) => {
            println!("[FAIL] Ed25519 verify failed: {:?}", e);
            std::process::exit(1);
        }
    }
}
