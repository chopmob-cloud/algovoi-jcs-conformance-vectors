// trust_gate deny-table gauntlet -- Rust impl.
use std::{env, fs};
use serde_json::Value;
fn blocks(mode: &Value, verdict: &str) -> bool {
	let m = match mode.as_str() { Some(s) => s, None => return false };
	if m.is_empty() || m == "off" { return false; }
	match m {
		"block_untrusted" => verdict == "UNTRUSTED",
		"require_trusted" => matches!(verdict, "UNTRUSTED" | "PROVISIONAL" | "INSUFFICIENT_EVIDENCE"),
		_ => false,
	}
}
fn main() {
	let d: Value = serde_json::from_str(&fs::read_to_string(env::args().nth(1).unwrap()).unwrap()).unwrap();
	let mut ok = 0; let mut fails: Vec<String> = vec![];
	for v in d["vectors"].as_array().unwrap() {
		if blocks(&v["mode"], v["verdict"].as_str().unwrap()) == v["expected_blocks"].as_bool().unwrap() { ok += 1 }
		else { fails.push(format!("{}: mismatch", v["id"].as_str().unwrap())) }
	}
	let total = d["vectors"].as_array().unwrap().len();
	for f in &fails { println!("  FAIL {}", f); }
	println!("TRUST-GATE-GAUNTLET rust {}/{}", ok, total);
	if ok != total || !fails.is_empty() { std::process::exit(1); }
}
