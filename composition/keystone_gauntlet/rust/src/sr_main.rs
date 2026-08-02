// settlement_round validity gauntlet -- Rust impl.
use std::{env, fs};
use serde_json::Value;
fn rpi_ok(v: &Value) -> bool { if v.is_boolean() { return false; } matches!(v.as_i64(), Some(n) if n > 0) }
fn main() {
	let d: Value = serde_json::from_str(&fs::read_to_string(env::args().nth(1).unwrap()).unwrap()).unwrap();
	let mut ok = 0; let mut fails: Vec<String> = vec![];
	for r in d["settlement_round_reject_vectors"].as_array().unwrap() {
		if !rpi_ok(&r["receipt"]["settlement_round"]) { ok += 1 } else { fails.push(format!("{}: bad round ACCEPTED", r["vector_id"].as_str().unwrap())) }
	}
	let acc = d["vectors"].as_array().unwrap().iter().find(|v| v["receipt"]["settlement_round"].is_i64()).unwrap();
	if rpi_ok(&acc["receipt"]["settlement_round"]) { ok += 1 } else { fails.push(format!("{}: valid round REJECTED", acc["vector_id"].as_str().unwrap())) }
	let total = d["settlement_round_reject_vectors"].as_array().unwrap().len() + 1;
	for f in &fails { println!("  FAIL {}", f); }
	println!("SETTLEMENT-ROUND-GAUNTLET rust {}/{}", ok, total);
	if ok != total || !fails.is_empty() { std::process::exit(1); }
}
