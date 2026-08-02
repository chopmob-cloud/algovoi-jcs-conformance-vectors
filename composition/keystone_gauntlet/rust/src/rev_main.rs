// revocation_ref fail-closed gauntlet -- Rust / serde_jcs.
use std::{env, fs};
use sha2::{Digest, Sha256};
use serde_json::{json, Value};
const REASONS: [&str; 6] = ["USER_REQUESTED", "COMPLIANCE_TRIGGERED", "EXPIRED", "KEY_COMPROMISE", "SUPERSEDED", "ADMIN"];
const STATUS: [&str; 4] = ["active", "suspended", "revoked", "inactive"];
fn is_ref(v: &Value) -> bool {
    match v.as_str() {
        Some(s) => s.len() == 71 && s.starts_with("sha256:") && s[7..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        None => false,
    }
}
fn hjcs(o: &Value) -> String {
    let c = serde_jcs::to_string(o).unwrap();
    let mut h = Sha256::new();
    h.update(c.as_bytes());
    format!("sha256:{}", h.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>())
}
fn rref(f: &Value) -> Result<String, ()> {
    let sref = f.get("subject_ref").cloned().unwrap_or(Value::Null);
    if !is_ref(&sref) { return Err(()); }
    let ms = f.get("revoked_at_ms").and_then(|v| v.as_u64()).ok_or(())?;
    let rc = f.get("reason_code").and_then(|v| v.as_str()).filter(|s| REASONS.contains(s)).ok_or(())?;
    let did = f.get("issuer_did").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).ok_or(())?;
    let ps = f.get("prev_status").and_then(|v| v.as_str()).filter(|s| STATUS.contains(s)).ok_or(())?;
    let ns = f.get("new_status").and_then(|v| v.as_str()).filter(|s| STATUS.contains(s)).ok_or(())?;
    let sq = f.get("seq").and_then(|v| v.as_u64()).ok_or(())?;
    let prev = match f.get("prev_revocation_ref") {
        None | Some(Value::Null) => Value::Null,
        Some(p) => { if !is_ref(p) { return Err(()); } p.clone() }
    };
    Ok(hjcs(&json!({"canon_version":"jcs-rfc8785-v1","type":"revocation_link","subject_ref":sref,
        "revoked_at_ms":ms,"reason_code":rc,"issuer_did":did,"prev_status":ps,"new_status":ns,"seq":sq,
        "prev_revocation_ref":prev})))
}
fn vchain(links: &Value) -> bool {
    let mut prev = Value::Null;
    for (i, l) in links.as_array().unwrap().iter().enumerate() {
        match l.get("seq").and_then(|v| v.as_u64()) { Some(s) if s as usize == i => {}, _ => return false }
        let lp = l.get("prev_revocation_ref").cloned().unwrap_or(Value::Null);
        if lp != prev { return false; }
        prev = Value::String(hjcs(l));
    }
    true
}
fn main() {
    let d: Value = serde_json::from_str(&fs::read_to_string(env::args().nth(1).unwrap()).unwrap()).unwrap();
    let mut ok = 0; let mut fails: Vec<String> = vec![];
    for v in d["vectors"].as_array().unwrap() {
        match rref(v) { Ok(r) if r == v["expected_revocation_ref"].as_str().unwrap() => ok += 1, _ => fails.push(v["id"].as_str().unwrap().into()) }
    }
    for n in d["negatives"].as_array().unwrap() { if rref(n).is_err() { ok += 1 } else { fails.push(n["id"].as_str().unwrap().into()) } }
    for t in d["tamper"].as_array().unwrap() {
        match rref(t) { Ok(r) if r != t["claimed_revocation_ref"].as_str().unwrap() => ok += 1, _ => fails.push(t["id"].as_str().unwrap().into()) }
    }
    for c in d["chain_valid"].as_array().unwrap() { if vchain(&c["links"]) { ok += 1 } else { fails.push(c["id"].as_str().unwrap().into()) } }
    for c in d["chain_invalid"].as_array().unwrap() { if !vchain(&c["links"]) { ok += 1 } else { fails.push(c["id"].as_str().unwrap().into()) } }
    let total = d["vectors"].as_array().unwrap().len() + d["negatives"].as_array().unwrap().len() + d["tamper"].as_array().unwrap().len() + d["chain_valid"].as_array().unwrap().len() + d["chain_invalid"].as_array().unwrap().len();
    for f in &fails { println!("  FAIL {}", f); }
    println!("REVOCATION-GAUNTLET rust {}/{}", ok, total);
    if ok != total || !fails.is_empty() { std::process::exit(1); }
}
