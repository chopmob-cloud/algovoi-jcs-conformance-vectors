# caip_edge_v1

An AlgoVoi-authored **adversarial** conformance set for the CAIP-2 / CAIP-10 / CAIP-19
chain-agnostic identifier grammar (ChainAgnostic/CAIPs). Negative-testing-first: it pins the
malformed, whitespace, Unicode-confusable, delimiter, injection and cross-level inputs a
validator MUST reject, plus a spine of accept controls that guard against over-rejection.

Chain-agnostic identifiers name the chain, account and asset a receipt refers to. When one is
folded into a canonicalised, content-addressed record it becomes part of the preimage: two
verifiers must agree on its exact bytes or their hashes diverge and the record stops
recomputing. So an identifier is not merely valid or not, it must be **byte-canonical**, and a
validator that accepts a non-canonical string is a correctness and a security defect.

## Contents

- `caip_edge_v1.json` — **102 vectors** (16 accept controls + 86 rejects) across 19 families.
  Each input is `input_b64` (base64 of the exact UTF-8 bytes, so control and non-ASCII cases
  survive any editor or code page); `input_display` is a Python repr; `family` groups the class;
  `naive_py_caret_dollar` records the verdict a naive Python `^...$` gives.
- `generate.py` — regenerates the JSON with a self-check against the correct reference.
- `runner_python.py` — independent Python reference (`\A..\Z`). Expected: **PASS 102/102**.
- `runner_node.mjs` — independent Node reference (`^..$`, no `m`). Expected: **PASS 102/102**.
- `runner_python_naive.py` — the Python trap: `^...$` over-accepts a trailing `\n`.
- `runner_node_naive.mjs` — the JavaScript trap: `^...$` **with the `m` flag**.
- `engines/` — the same 102 inputs as `corpus.tsv` (`expectation \t kind \t hex`) plus a
  standalone runner per engine: `runner.go`, `runner.rs` (deliberately a **no-regex hand
  parser**, an independent check that leans on no regex engine at all), `Runner.java`,
  `runner.php`, `runner.rb`, and `engines/rust-regex/` (a small cargo crate exercising the Rust
  `regex` crate's anchors directly). Each reads `corpus.tsv` from the working directory.
- `run_all.sh`, `LICENSE`.

The two correct runners re-implement the validators from scratch and import no shared library,
so agreement across them (204/204 verdicts) is a genuine cross-implementation result.

`corpus.tsv` carries the identical input bytes to `caip_edge_v1.json`: the TSV hex and the JSON
base64 decode to the same 102 byte sequences (sha256 over the concatenated inputs of either
representation is `b2fcd5f39269155b6cc77120b549adcb3291becb7c818f78031818b0ff122c96`), so every
engine validates the same corpus rather than a drifted copy.

## Measured anchor behaviour (7 engines)

Every engine validates all 102 vectors correctly under the correct anchors. The interesting
column is the third: how many of the 86 reject vectors a **naive** `^...$` wrongly accepts in
that language. This is measured, not reasoned, and it is what makes the trailing-newline
divergence concrete.

| Engine | Correct | Naive `^...$` over-accepts | Trailing `\n` |
| --- | --- | --- | --- |
| Python (`re`) | 102/102 | 3 | accepted |
| Java (`find()` + `$`) | 102/102 | 8 | accepted |
| PHP (PCRE) | 102/102 | 3 | accepted |
| Ruby (Onigmo) | 102/102 | 5 | accepted |
| Go (RE2) | 102/102 | 0 | rejected |
| Rust (`regex` crate) | 102/102 | 0 | rejected |
| JavaScript (no `m`) | 102/102 | 0 | rejected |

The two engines that reject it are not safe by accident: opting into line anchors reverts them
to the same failure. Rust with `(?m)` over-accepts 5 reject vectors, and JavaScript with the
`m` flag over-accepts 9 including newline injection. The lesson is the anchor, not the
language.

## Families (19)

`control` (16), `unicode_ws` (10), `trail_ctrl` (10), `struct` (9), `injection` (8),
`charset_ns` (7), `unicode_confusable` (7), `xlevel` (6), `charset_ref` (5), `charset_addr` (5),
`lead_ctrl` (4), `embed_ctrl` (2), and the six length boundaries (`len_ns`, `len_ref`,
`len_addr`, `len_asset_ns`, `len_asset_ref`, `len_token`, 2 each), plus `empty` (1).

## The anchor traps (why cross-language matters)

The regex anchor is where two validators that "both do CAIP" diverge, and the divergence is
language-dependent:

- **Python** `$` (no `MULTILINE`) matches at end-of-string *or just before a single trailing
  `\n`*. So `^...$` wrongly accepts `eip155:1\n`. Correct Python anchors with `\A` and `\Z`.
  `runner_python_naive.py` reproduces the recorded `naive_py_caret_dollar` verdicts and shows
  the divergence is exactly the three single-trailing-`\n` rejects, no under-rejections.
- **JavaScript** `$` **with the `m` flag** matches at every line boundary, so `^id$` matches
  when *any line* of the input is a valid identifier. That accepts trailing terminators
  (LF, CR, CRLF, U+2028, U+2029), leading newlines, and, most seriously, **newline-injection**:
  `eip155:1\n<script>` passes because its first line is a valid id. Correct JS is `^..$`
  without `m`. `runner_node_naive.mjs` shows nine over-acceptances, all inputs with a valid
  line, no under-rejections.

A single-language self-check surfaces neither trap; a cross-language adversarial set surfaces
both. (During authoring, a literal U+2028 placed in a `//` comment of the JS demonstrator
terminated the comment and broke the parse, the same line-terminator hazard one layer up; the
runner source is therefore pure ASCII with backslash-u escapes.)

## Grammar (verbatim from CAIP-2/10/19)

```
chain_id    = namespace ":" reference     namespace [-a-z0-9]{3,8}  reference [-_a-zA-Z0-9]{1,32}
account_id  = chain_id ":" address        address   [-.%a-zA-Z0-9]{1,128}
asset_type  = chain_id "/" ns ":" ref     ns [-a-z0-9]{3,8}   ref [-.%a-zA-Z0-9]{1,128}
asset_id    = asset_type "/" token_id     token_id  [-.%a-zA-Z0-9]{1,78}
```

## Run

```bash
python runner_python.py         # PASS 102/102
node   runner_node.mjs          # PASS 102/102
python runner_python_naive.py   # Python trap: 3 trailing-\n over-acceptances
node   runner_node_naive.mjs    # JS m-flag trap: 9 over-acceptances incl. newline injection
```

The other engines each read `corpus.tsv` from the working directory, so run them from
`engines/`:

```bash
cd engines
go run runner.go                                    # Go(RE2)      correct 102/102
java Runner.java                                    # Java         correct 102/102
php runner.php                                      # PHP(PCRE)    correct 102/102
ruby runner.rb                                      # Ruby(Onigmo) correct 102/102
rustc -O -o /tmp/r runner.rs && /tmp/r              # Rust hand parser, no regex
cargo run --quiet --manifest-path rust-regex/Cargo.toml   # Rust(regex crate)
```

Apache-2.0. Copyright 2026 AlgoVoi (chopmob@gmail.com).
