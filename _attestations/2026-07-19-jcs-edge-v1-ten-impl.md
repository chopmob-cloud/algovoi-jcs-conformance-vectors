# Attestation: jcs_edge_v1 cross-validated across ten implementations

**Date:** 2026-07-19
**Set:** `jcs_edge_v1` (10 vectors, 2 pair invariants). Pins the RFC 8785
canonicalisation edge classes that ad-hoc "sorted-keys JSON" gets wrong and that a
single-SDK self-check cannot catch: UTF-8 generation of U+2028 / U+2029 (section
3.2.4), supplementary-plane key ordering by UTF-16 code units (section 3.2.3), and
the 1.0-versus-1 number form (section 3.2.2.3), plus the mandatory short escapes
and literal solidus / and- / less-than / greater-than.

**Result:** 10 vectors x 10 implementations = **100/100 byte-for-byte agreements**.
This is the first corpus set exercised across all ten implementations from
inception.

| Implementation | Library | Result | Environment |
|---|---|---|---|
| Python | rfc8785 0.1.4 (Trail of Bits) | 10/10 | reference |
| JavaScript | canonicalize (@algovoi/substrate) | 10/10 | local |
| Ruby | json-canonicalization | 10/10 | local |
| Go | gowebpki/jcs | 10/10 | local |
| Java | erdtman/java-json-canonicalization 1.1 | 10/10 | local |
| C#/.NET | Baqhub.Packages.JsonCanonicalization | 10/10 | local |
| PHP | inline pure-stdlib JCS (AlgoVoi-authored, patched) | 10/10 | local |
| Rust | serde_jcs 0.2.0 | 10/10 | VM2 clean-box (rust:latest, rustc 1.97.1) |
| Elixir | jcs 0.2.0 (pzingg/jcs) | 10/10 | VM2 clean-box (elixir:latest, 1.20.2/OTP 29) |
| Kotlin/JVM | erdtman/java-json-canonicalization 1.1 | 10/10 | VM2 clean-box (temurin 17.0.19) |

## A real divergence caught, and the patch that closes it

The first pass surfaced a genuine non-conformance in the corpus's own
**AlgoVoi-authored inline PHP JCS** (not a third-party library): it escaped
U+2028 / U+2029 and did not implement the ES6 integral-float form. These never
appeared before because the earlier receipt formats contained neither line
separators nor floats. `jcs_edge_v1` is the first set to include them, so it is the
first to exercise the gap.

The fix is the PHP instance of the same serialiser patch we developed for Go
(a2a-go#368, where Go's `encoding/json` escapes U+2028 / U+2029 even with
`SetEscapeHTML(false)`):

- **UTF-8 generation (3.2.4):** add `JSON_UNESCAPED_LINE_TERMINATORS` to the string
  and key encoding so U+2028 / U+2029 stay literal UTF-8. `JSON_UNESCAPED_UNICODE`
  alone does not cover them.
- **Number form (3.2.2.3):** a float whose value is integral canonicalises to the
  integer form (1.0 -> 1).

With the patch (`vectors/jcs_edge_v1/runner_php.php`) PHP reproduces all ten
vectors byte-for-byte. This is the thesis made concrete: conformant JCS libraries
agree on the hard cases; a hand-rolled serialiser silently diverges until a second,
independent implementation recomputes the bytes; the corpus is what catches it.

The other nine implementations were conformant on these cases without modification.

## Method

Each implementation recomputes `base64(JCS(preimage))` and `sha256(JCS(preimage))`
per vector and compares byte-for-byte against `expected_jcs_bytes_b64` and
`expected_sha256`. The expected values are produced by the Python reference
(rfc8785) and independently reproduced by the other nine. Because every
implementation matches the same reference values, each agrees with all others by
construction.
