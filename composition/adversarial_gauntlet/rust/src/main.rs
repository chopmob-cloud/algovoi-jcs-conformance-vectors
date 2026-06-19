// Adversarial gauntlet runner -- Rust (independent reimplementation, no algovoi import).
// Same three checks; accept the control, reject all 11 mutations.
// Usage: cargo run --release -- /path/to/adversarial_isolation_v1.json
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::{env, fs, process};

fn is_hex64(v: &Value) -> bool {
    v.as_str().map_or(false, |s| {
        s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn is_uint(v: &Value) -> bool {
    v.as_u64().is_some() // false for negative, bool, string, float
}

fn nestr(v: &Value) -> bool {
    v.as_str().map_or(false, |s| !s.is_empty())
}

// sorted-key compact JSON via BTreeMap; byte-identical to RFC 8785 JCS for ASCII/int payloads.
fn jcs_flat(payload: &Value) -> String {
    let obj = payload.as_object().cloned().unwrap_or_default();
    let sorted: BTreeMap<String, Value> = obj.into_iter().collect();
    serde_json::to_string(&sorted).unwrap()
}

fn sha(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|x| format!("{:02x}", x)).collect()
}

fn check_transition(o: &Value) -> bool {
    if !o.is_object() {
        return false;
    }
    if !is_hex64(&o["action_ref"]) || !nestr(&o["state"]) {
        return false;
    }
    for k in ["transition_timestamp_ms", "authority_verified_at_ms", "revocation_check_at_ms"] {
        if !is_uint(&o[k]) {
            return false;
        }
    }
    true
}

fn check_action_ref(o: &Value) -> bool {
    if !o.is_object() {
        return false;
    }
    for k in ["agent_id", "action_type", "scope"] {
        if !nestr(&o[k]) {
            return false;
        }
    }
    is_uint(&o["timestamp_ms"])
}

fn check_audit_chain(rows: &Value) -> bool {
    let arr = match rows.as_array() {
        Some(a) if !a.is_empty() => a,
        _ => return false,
    };
    let mut prev = String::new();
    for (i, r) in arr.iter().enumerate() {
        if !r.is_object() {
            return false;
        }
        match r["chain_position"].as_u64() {
            Some(cp) if cp == i as u64 => {}
            _ => return false,
        }
        if i == 0 {
            if !r["prev_hash"].is_null() {
                return false;
            }
        } else {
            match r["prev_hash"].as_str() {
                Some(ph) if ph == prev => {}
                _ => return false,
            }
        }
        let recomputed = sha(&jcs_flat(&r["payload"]));
        match r["content_hash"].as_str() {
            Some(ch) if ch == recomputed => prev = ch.to_string(),
            _ => return false,
        }
    }
    true
}

fn main() {
    let path = env::args().nth(1).expect("vector file path required");
    let data: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let (mut ok, mut total) = (0, 0);
    for v in data["vectors"].as_array().unwrap() {
        total += 1;
        let accepted = match v["check"].as_str().unwrap() {
            "transition_preimage" => check_transition(&v["input"]),
            "action_ref" => check_action_ref(&v["input"]),
            "audit_chain" => check_audit_chain(&v["input"]),
            _ => false,
        };
        let verdict = if accepted { "accept" } else { "reject" };
        let expected = if v["expectation"] == "reject" { "reject" } else { "accept" };
        let good = verdict == expected;
        if good {
            ok += 1;
        }
        println!(
            "{} {} expect={} {}",
            v["vector_id"].as_str().unwrap(),
            verdict,
            expected,
            if good { "OK" } else { "MISMATCH" }
        );
    }
    println!("GAUNTLET rust {}/{}", ok, total);
    process::exit(if ok == total { 0 } else { 1 });
}
