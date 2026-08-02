// Keystone L3 fail-closed gauntlet -- Rust / serde_jcs 0.2.0.
// Independent reimplementation of decision_audit_ref (no algovoi import).
// Usage: cargo run --quiet -- <keystone_decision_audit_v1.json>
use std::env;
use std::fs;
use sha2::{Digest, Sha256};
use serde_json::{json, Map, Value};

fn is_ref(v: &Value) -> bool {
    match v.as_str() {
        Some(s) => s.len() == 71 && s.starts_with("sha256:")
            && s[7..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        None => false,
    }
}

fn dar(src: &Value, with_screen: bool) -> Result<String, String> {
    let mut m = Map::new();
    for k in ["decision_ref", "passport_credential_ref", "mandate_ref", "policy_bound_ref"] {
        let val = src.get(k).cloned().unwrap_or(Value::Null);
        if !is_ref(&val) {
            return Err(format!("{} must be sha256: ref", k));
        }
        m.insert(k.to_string(), val);
    }
    if with_screen {
        if let Some(sbr) = src.get("screen_binding_ref") {
            if !sbr.is_null() {
                if !is_ref(sbr) {
                    return Err("screen_binding_ref must be sha256: ref".into());
                }
                m.insert("screen_binding_ref".to_string(), sbr.clone());
            }
        }
    }
    let obj = Value::Object(m);
    let canon = serde_jcs::to_string(&obj).map_err(|e| e.to_string())?;
    let mut h = Sha256::new();
    h.update(canon.as_bytes());
    let hexs: String = h.finalize().iter().map(|b| format!("{:02x}", b)).collect();
    Ok(format!("sha256:{}", hexs))
}

fn main() {
    let path = env::args().nth(1).expect("vector path");
    let d: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let mut ok = 0;
    let mut fails: Vec<String> = vec![];
    for v in d["vectors"].as_array().unwrap() {
        match dar(v, true) {
            Ok(got) if got == v["expected_decision_audit_ref"].as_str().unwrap() => ok += 1,
            _ => fails.push(format!("{}: accept-mismatch", v["id"].as_str().unwrap())),
        }
    }
    for n in d["negatives"].as_array().unwrap() {
        let id = n["id"].as_str().unwrap();
        if n["must"].as_str().unwrap() == "reject" {
            match dar(n, true) {
                Err(_) => ok += 1,
                Ok(_) => fails.push(format!("{}: invalid ACCEPTED", id)),
            }
        } else {
            match dar(n, true) {
                Ok(got) if got != n["claimed_decision_audit_ref"].as_str().unwrap() => ok += 1,
                Ok(_) => fails.push(format!("{}: tamper NOT detected", id)),
                Err(e) => fails.push(format!("{}: {}", id, e)),
            }
        }
    }
    let v0 = &d["vectors"][0];
    match (dar(v0, true), dar(v0, false)) {
        (Ok(a), Ok(b)) if a != b => ok += 1,
        _ => fails.push("screen-distinctness collision".into()),
    }
    let mut bad = v0.clone();
    bad["decision_ref"] = json!("bad");
    match dar(&bad, true) {
        Err(_) => ok += 1,
        Ok(_) => fails.push("malformed-ref accepted".into()),
    }
    let total = d["vectors"].as_array().unwrap().len() + d["negatives"].as_array().unwrap().len() + 2;
    for f in &fails {
        println!("  FAIL {}", f);
    }
    println!("KEYSTONE-GAUNTLET rust {}/{}", ok, total);
    if ok != total || !fails.is_empty() {
        std::process::exit(1);
    }
}
