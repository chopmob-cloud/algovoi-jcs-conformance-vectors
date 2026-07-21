// Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0.
// caip_edge_v1 Rust runner: a regex-FREE hand parser (std only, no crates). It cross-validates
// the grammar in a third language without any regex engine, so agreement here is independent of
// regex-anchor behaviour entirely.
use std::fs;

fn ns(c: char) -> bool { c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' }
fn refc(c: char) -> bool { c.is_ascii_alphanumeric() || c == '-' || c == '_' }
fn addr(c: char) -> bool { c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '%' }
fn cls(s: &str, lo: usize, hi: usize, f: fn(char) -> bool) -> bool {
    let n = s.chars().count();
    n >= lo && n <= hi && s.chars().all(f)
}
fn is2(s: &str) -> bool {
    let p: Vec<&str> = s.split(':').collect();
    p.len() == 2 && cls(p[0], 3, 8, ns) && cls(p[1], 1, 32, refc)
}
fn is10(s: &str) -> bool {
    let p: Vec<&str> = s.split(':').collect();
    p.len() == 3 && cls(p[0], 3, 8, ns) && cls(p[1], 1, 32, refc) && cls(p[2], 1, 128, addr)
}
fn is19(s: &str) -> bool {
    let sl: Vec<&str> = s.split('/').collect();
    let (chain, ap, tok) = match sl.len() {
        2 => (sl[0], sl[1], None),
        3 => (sl[0], sl[1], Some(sl[2])),
        _ => return false,
    };
    if !is2(chain) { return false; }
    let a: Vec<&str> = ap.split(':').collect();
    if a.len() != 2 || !cls(a[0], 3, 8, ns) || !cls(a[1], 1, 128, addr) { return false; }
    tok.map_or(true, |t| cls(t, 1, 78, addr))
}
fn unhex(h: &str) -> String {
    let bytes: Vec<u8> = (0..h.len()).step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}
fn main() {
    let data = fs::read_to_string("corpus.tsv").expect("corpus.tsv");
    let (mut n, mut pass) = (0, 0);
    for line in data.lines() {
        let p: Vec<&str> = line.splitn(3, '\t').collect();
        if p.len() < 3 { continue; }
        let (exp, kind, s) = (p[0], p[1], unhex(p[2]));
        let got = match kind { "caip2" => is2(&s), "caip10" => is10(&s), _ => is19(&s) };
        if got == (exp == "accept") { pass += 1; }
        n += 1;
    }
    println!("Rust(no-regex hand-parser)  correct {}/{}", pass, n);
    std::process::exit(if pass == n { 0 } else { 1 });
}
