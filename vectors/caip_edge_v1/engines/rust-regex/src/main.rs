// Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0.
//
// caip_edge_v1 runner for the Rust `regex` crate.
//
// Reads corpus.tsv from the current directory: expectation \t kind \t hex(input bytes).
//
// Three anchor modes are evaluated so Rust's behaviour is measured, not assumed:
//   correct    \A ... \z   absolute start/end of haystack
//   naive      ^  ... $    in the regex crate these are haystack anchors too (no multi_line),
//                          so unlike Python/PCRE/Onigmo there is NO trailing-newline exception
//                          and this mode is expected to over-accept nothing
//   multiline  (?m)^...$   opts into line anchors, the Rust analogue of the JavaScript m-flag
//                          trap, which does over-accept any input containing a valid line
//
// A non-UTF-8 input cannot be a canonical identifier, so it is treated as a reject.

use regex::Regex;
use std::fs;

const NS: &str = r"[-a-z0-9]{3,8}";
const REF: &str = r"[-_a-zA-Z0-9]{1,32}";
const ADDR: &str = r"[-.%a-zA-Z0-9]{1,128}";
const TOKEN: &str = r"[-.%a-zA-Z0-9]{1,78}";

fn bodies() -> [(&'static str, String); 3] {
    let chain = format!("{}:{}", NS, REF);
    [
        ("caip2", chain.clone()),
        ("caip10", format!("{}:{}", chain, ADDR)),
        ("caip19", format!("{}/{}:{}(/{})?", chain, NS, ADDR, TOKEN)),
    ]
}

fn build(prefix: &str, suffix: &str, extra: &str) -> Vec<(String, Regex)> {
    bodies()
        .iter()
        .map(|(kind, body)| {
            let pat = format!("{}{}{}{}", extra, prefix, body, suffix);
            (kind.to_string(), Regex::new(&pat).expect("regex"))
        })
        .collect()
}

fn matches(set: &[(String, Regex)], kind: &str, s: &str) -> bool {
    set.iter()
        .find(|(k, _)| k == kind)
        .map(|(_, re)| re.is_match(s))
        .unwrap_or(false)
}

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).expect("hex"))
        .collect()
}

fn main() {
    let correct = build(r"\A", r"\z", "");
    let naive = build("^", "$", "");
    let multiline = build("^", "$", "(?m)");

    let data = fs::read_to_string("corpus.tsv").expect("corpus.tsv in current directory");

    let (mut n, mut pass, mut trap_naive, mut trap_ml) = (0usize, 0usize, 0usize, 0usize);

    for line in data.lines().filter(|l| !l.trim().is_empty()) {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 3 {
            continue;
        }
        let (expectation, kind, hex) = (cols[0], cols[1], cols[2]);
        n += 1;

        let bytes = unhex(hex);
        // a non-UTF-8 sequence is not a canonical identifier
        let text = match std::str::from_utf8(&bytes) {
            Ok(t) => t,
            Err(_) => {
                if expectation == "reject" {
                    pass += 1;
                }
                continue;
            }
        };

        let want_accept = expectation == "accept";
        if matches(&correct, kind, text) == want_accept {
            pass += 1;
        }
        if !want_accept {
            if matches(&naive, kind, text) {
                trap_naive += 1;
            }
            if matches(&multiline, kind, text) {
                trap_ml += 1;
            }
        }
    }

    println!(
        "Rust(regex crate) correct {}/{} | naive ^..$ over-accepts {} reject-vectors | (?m) over-accepts {} reject-vectors",
        pass, n, trap_naive, trap_ml
    );

    if pass != n {
        std::process::exit(1);
    }
}
