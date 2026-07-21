// Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE at the repo root.
//
// jws_anchor_v1 signature + anchor runner (Rust / ed25519-dalek).
// Asserts, for every signed vector: the compact JWS verifies under the RFC 8032
// section 7.1 key, and the anchor is sha256 of the RAW SIGNED BYTES.
// Usage: cargo run --release --quiet -- <jws_anchor_v1.json>

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::{env, fs};

fn strip(h: &str) -> &str {
    match h.find(':') {
        Some(i) => &h[i + 1..],
        None => h,
    }
}

fn main() {
    let path = env::args().nth(1).expect("usage: sig_runner_rust <set.json>");
    let data: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("read set")).expect("parse set");

    let pub_hex = data["signing_key"]["public_key_hex"].as_str().expect("public_key_hex");
    let pub_bytes: [u8; 32] = hex::decode(pub_hex).expect("hex").try_into().expect("32 bytes");
    let vk = VerifyingKey::from_bytes(&pub_bytes).expect("verifying key");

    let (mut pass, mut fail) = (0usize, 0usize);
    let mut check = |id: &str, what: &str, ok: bool| {
        if ok { pass += 1 } else { fail += 1; println!("  FAIL {id} ({what})") }
    };

    for v in data["vectors"].as_array().expect("vectors") {
        if v["anchor_rule"].as_str() != Some("signed_bytes") {
            continue;
        }
        let token = v["input"].as_str()
            .or_else(|| v["issuer_jwt"].as_str())
            .or_else(|| v["presentation"].as_str());
        let token = match token {
            Some(t) => t,
            None => continue, // recanon-negative carries no token
        };
        let id = v["vector_id"].as_str().unwrap_or("?");
        let jwt = token.split('~').next().unwrap_or(token);

        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            check(id, "not a compact JWS", false);
            continue;
        }
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap_or_default();
        let ok = <[u8; 64]>::try_from(sig_bytes.as_slice())
            .map(|b| vk.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &Signature::from_bytes(&b)).is_ok())
            .unwrap_or(false);
        check(id, "ed25519 verify", ok);

        let want = v["expected_anchor"].as_str().or_else(|| v["presentation_hash"].as_str());
        if let Some(want) = want {
            let digest = hex::encode(Sha256::digest(token.as_bytes()));
            check(id, "anchor = sha256(raw signed bytes)", digest == strip(want));
        }
    }

    println!("{}/{} PASS", pass, pass + fail);
    if fail > 0 {
        std::process::exit(1);
    }
}
