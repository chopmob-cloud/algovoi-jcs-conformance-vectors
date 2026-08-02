// Keystone L3 gauntlet -- guard_context, Rust / serde_jcs.
// Usage: cargo run --bin gc -- <keystone_guard_context_v1.json>
use std::env;
use std::fs;
use sha2::{Digest, Sha256};
use serde_json::{json, Value};

fn is_ref(v: &Value) -> bool {
    match v.as_str() {
        Some(s) => s.len() == 71 && s.starts_with("sha256:")
            && s[7..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        None => false,
    }
}

fn gcr(src: &Value) -> Result<String, String> {
    let ts = src.get("guard_timestamp_ms").cloned().unwrap_or(Value::Null);
    let ts_u = ts.as_u64().ok_or_else(|| "guard_timestamp_ms must be non-negative integer".to_string())?;
    for k in ["policy_ref", "mandate_ref", "passport_credential_ref"] {
        if !is_ref(&src.get(k).cloned().unwrap_or(Value::Null)) {
            return Err(format!("{} must be sha256: ref", k));
        }
    }
    let obj = json!({
        "canon_version": "jcs-rfc8785-v1", "type": "guard_context",
        "guard_timestamp_ms": ts_u,
        "policy_ref": src["policy_ref"], "mandate_ref": src["mandate_ref"], "passport_credential_ref": src["passport_credential_ref"]
    });
    let canon = serde_jcs::to_string(&obj).map_err(|e| e.to_string())?;
    let mut h = Sha256::new();
    h.update(canon.as_bytes());
    Ok(format!("sha256:{}", h.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>()))
}

fn main() {
    let path = env::args().nth(1).expect("vector path");
    let d: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let mut ok = 0;
    let mut fails: Vec<String> = vec![];
    for v in d["vectors"].as_array().unwrap() {
        match gcr(v) {
            Ok(got) if got == v["expected_guard_context_ref"].as_str().unwrap() => ok += 1,
            _ => fails.push(format!("{}: accept-mismatch", v["id"].as_str().unwrap())),
        }
    }
    for n in d["negatives"].as_array().unwrap() {
        let id = n["id"].as_str().unwrap();
        if n["must"].as_str().unwrap() == "reject" {
            match gcr(n) { Err(_) => ok += 1, Ok(_) => fails.push(format!("{}: invalid ACCEPTED", id)) }
        } else {
            match gcr(n) {
                Ok(got) if got != n["claimed_guard_context_ref"].as_str().unwrap() => ok += 1,
                Ok(_) => fails.push(format!("{}: tamper NOT detected", id)),
                Err(e) => fails.push(format!("{}: {}", id, e)),
            }
        }
    }
    let v0 = &d["vectors"][0];
    let mut plus = v0.clone();
    plus["guard_timestamp_ms"] = json!(v0["guard_timestamp_ms"].as_u64().unwrap() + 1);
    match (gcr(v0), gcr(&plus)) {
        (Ok(a), Ok(b)) if a != b => ok += 1,
        _ => fails.push("moment-distinctness collision".into()),
    }
    let mut flt = v0.clone();
    flt["guard_timestamp_ms"] = json!(1720000000000.5);
    match gcr(&flt) { Err(_) => ok += 1, Ok(_) => fails.push("float-ts accepted".into()) }
    let total = d["vectors"].as_array().unwrap().len() + d["negatives"].as_array().unwrap().len() + 2;
    for f in &fails { println!("  FAIL {}", f); }
    println!("KEYSTONE-GAUNTLET-GC rust {}/{}", ok, total);
    if ok != total || !fails.is_empty() { std::process::exit(1); }
}
