# caip_edge_v1: seven-engine verdict attestation

**Date:** 2026-07-21
**Set:** `vectors/caip_edge_v1/` (102 vectors: 16 accept controls + 86 rejects, 19 families)
**Spec anchored:** ChainAgnostic/CAIPs CAIP-2, CAIP-10, CAIP-19 identifier grammar
**Licence:** Apache-2.0, AlgoVoi-authored

## What this set claims, and what it does not

`caip_edge_v1` is a **grammar** set, not a JCS canonicalisation set. It carries no per-vector
canonical-bytes recompute, so it is recorded under `grammar_sets` in `manifest.json` and is
**not** folded into `total_anchor_sets` / `total_vectors`.

Following the adversarial-set rule, the two claims are kept separate:

- **Claim 1 (input bytes).** Each vector's input is pinned as exact bytes. The set ships two
  representations, `input_b64` in `caip_edge_v1.json` and hex in `engines/corpus.tsv`, and they
  decode to identical byte sequences. sha256 over the concatenation of all 102 inputs is
  `b2fcd5f39269155b6cc77120b549adcb3291becb7c818f78031818b0ff122c96` computed from **either**
  representation, so every engine below validated the same corpus rather than a drifted copy.
- **Claim 2 (verdicts).** The accept/reject verdicts are reference-implementation
  proof-of-record across the engines listed below. This is a verdict-agreement claim, **not** a
  canonical-byte claim.

## Engine matrix

All runs on a clean box (Docker, VM2), each engine reading the LF-normalised `corpus.tsv`
(sha256 `8e11ce56fed75c927eeba84b1b09344dc2f9e8f529231ae744ac9a3fffe6e48d`), except the Python
and Node references which read `caip_edge_v1.json` directly.

| Engine | Version | Correct | Naive `^...$` over-accepts |
| --- | --- | --- | --- |
| Python `re` | 3.12.13 | 102/102 | 3 |
| JavaScript (Node) | v20.20.2 | 102/102 | 0 (9 with the `m` flag) |
| Go RE2 | go1.26.5 | 102/102 | 0 |
| Rust `regex` crate | rustc 1.97.1 | 102/102 | 0 (5 with `(?m)`) |
| Rust hand parser (no regex) | rustc 1.97.1 | 102/102 | n/a |
| Java `find()` + `$` | OpenJDK 21.0.11 | 102/102 | 8 |
| PHP PCRE | 8.5.8 | 102/102 | 3 |
| Ruby Onigmo | 3.4.10 | 102/102 | 5 |

Eight configurations across seven languages. The Rust hand parser is included deliberately as
an implementation that depends on no regex engine at all, so the grammar itself is checked
independently of regex semantics.

## The result that matters

Every engine validates all 102 vectors correctly **under the correct anchors**. The divergence
appears only in the naive column, and it is language-dependent:

- **Python, Java, PHP, Ruby** over-accept a trailing newline under a naive `^...$`. In Python
  `$` matches at end-of-string *or* just before a single trailing `\n`; Java's `find()` and
  PCRE behave analogously; Ruby's `$` is line-anchored by construction.
- **Go, Rust, JavaScript** do not: their `$` is an end-of-haystack anchor.

Those two groups are not safe and unsafe languages. Opting into line anchors reverts the safe
group to the same defect: Rust with `(?m)` over-accepts 5 reject vectors and JavaScript with the
`m` flag over-accepts 9, including newline injection (`eip155:1\n<script>` passes because its
first line is a valid identifier). The defect is the anchor, not the language.

This is the practical consequence for content-addressed records: a producer whose validator
accepts `eip155:1\n` hashes the identifier with the newline, while a verifier in another
language hashes it without. Both believe they validated correctly, and the digests differ by
one byte, so the record stops recomputing.

## Reproduction

```bash
cd vectors/caip_edge_v1
python runner_python.py         # PASS 102/102
node   runner_node.mjs          # PASS 102/102
python runner_python_naive.py   # 3 trailing-newline over-acceptances
node   runner_node_naive.mjs    # 9 over-acceptances with the m flag

cd engines
go run runner.go
java Runner.java
php runner.php
ruby runner.rb
rustc -O -o /tmp/r runner.rs && /tmp/r
cargo run --quiet --manifest-path rust-regex/Cargo.toml
```

`generate.py` regenerates `caip_edge_v1.json` byte-for-byte, so the set is reproducible from
source rather than merely checked in.
