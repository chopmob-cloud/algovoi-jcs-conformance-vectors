# Attestation: jws_anchor_v1 cross-validated across ten implementations

**Date:** 2026-07-21
**Set:** `jws_anchor_v1` (6 vectors, 4 invariants). Pins the **anchoring** rule for signed
receipts and mandates: which bytes an implementation must hash. `jcs_edge_v1` pins the
*canonicalisation* floor, given an object, the exact canonical bytes. This set pins the layer
above it, given a **signed** object, what you hash. The nastier failure is that both parties can
be perfectly JCS-conformant and still disagree on the anchor, because one re-canonicalises a
decoded payload instead of hashing what was actually signed.

**Result:** all ten implementations agree. See the scope split below: this set is deliberately
**not** a single uniform ten-by-six grid, and saying so is part of the attestation.

## Scope split, stated explicitly

Five of the six vectors carry `anchor_rule: signed_bytes`, which is not a canonicalisation
operation at all, and four of them carry an Ed25519 signature. So the set decomposes into two
claims validated by two different populations. No result below is extrapolated from the other.

| Claim | What is asserted | Population | Result |
|---|---|---|---|
| **JCS side** | `sha256(JCS(preimage))` and the canonical bytes, for the three places the set depends on RFC 8785 | **10 implementations** | 3 vectors x 10 = **30/30** |
| **Signature + anchoring side** | the compact JWS verifies under the RFC 8032 section 7.1 key, and the anchor is `sha256` of the **raw signed bytes** | **8 crypto-capable implementations** | **8/8 implementations pass** |

The crypto-capable population matches the precedent set by `rfc9421_proxy_chain_v1`
(Python, Node, Go, Rust, Java, PHP/libsodium, .NET, Ruby). Elixir and Kotlin participate in the
JCS side only, and are not claimed for signature verification.

## JCS side: ten implementations, 30/30

The three JCS-dependent points are extracted by `derive_jcs_side.py` into
`jws_anchor_v1_jcs_side.json`, in the shape this corpus's existing generic preimage runners
already consume. The script recomputes each value from the set itself and **fails closed** on
any disagreement, so the derived fixture cannot drift from the vectors it represents.

| Derived vector | Asserts |
|---|---|
| `jws-anchor-005-jcs` | the one genuinely unsigned vector, anchored by `sha256(JCS(object))` |
| `jws-anchor-002-recanon` | `sha256(JCS(decoded payload of 001))`, the value a re-canonicalising verifier wrongly produces |
| `jws-anchor-006-recanon` | the canon-sensitive payload, carrying U+2028 and the `1.0` integral-float form |

| Implementation | Library | Result | Environment |
|---|---|---|---|
| Python | rfc8785 (Trail of Bits) | 3/3 | VM2 clean-box, 3.12.13 |
| JavaScript | canonicalize | 3/3 | VM2 clean-box, Node 20.20.2 |
| Ruby | json-canonicalization | 3/3 | VM2 clean-box, 3.4.10 |
| Go | gowebpki/jcs | 3/3 | VM2 clean-box, go1.26.5 |
| Java | erdtman/java-json-canonicalization 1.1 | 3/3 | VM2 clean-box, temurin 21 |
| C#/.NET | Baqhub.Packages.JsonCanonicalization | 3/3 | VM2 clean-box, SDK 9.0.316 |
| PHP | inline pure-stdlib JCS (AlgoVoi-authored, patched) | 3/3 | VM2 clean-box, 8.5.8 |
| Rust | serde_jcs 0.2.0 | 3/3 | VM2 clean-box, rustc 1.97.1 |
| Elixir | jcs 0.2.0 (pzingg/jcs) | 3/3 | VM2 clean-box, 1.20.2/OTP 29 |
| Kotlin/JVM | erdtman/java-json-canonicalization 1.1 | 3/3 | VM2 clean-box, temurin 21 |

### A stale harness copy caught on first contact

The first pass failed in PHP, on `throw new Exception("floats unsupported")`, with a string
encoder that also lacked `JSON_UNESCAPED_LINE_TERMINATORS`. The cause was that the generic PHP
runner carried by the pre-2026-07-19 attestation directories predates the patch that
`jcs_edge_v1` produced, and `jws-anchor-006-recanon` carries **both** triggering conditions,
U+2028 and `1.0`, in a single payload.

So this set independently re-detected both known gaps in an unpatched copy, immediately, without
being designed to look for them. `sig_runner`/`runner_php.php` in this directory carries the
patched canonicaliser, with both patches documented inline. Note for future sets: the patched
inline PHP JCS currently lives only in `vectors/jcs_edge_v1/runner_php.php` and here; the other
`_attestations/*` copies remain unpatched. They fail loudly rather than silently, so no published
value is affected.

## Signature and anchoring side: eight implementations

Each implementation independently verifies the four signed tokens under the RFC 8032 section 7.1
Test 1 public key `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`, and
recomputes each anchor as `sha256` of the raw signed bytes. For the SD-JWT vectors the signature
covers the JWT segment before the first `~`, while the anchor is taken over the exact token form
the vector names, which is precisely the distinction that makes anchoring a presentation a bug.

| Implementation | Ed25519 provider | Result |
|---|---|---|
| Python | cryptography | 19/19 (full in-set runner) |
| JavaScript | node:crypto | 19/19 (full in-set runner) |
| Go | stdlib crypto/ed25519 | 8/8 |
| PHP | libsodium (bundled since 7.2) | 8/8 |
| Ruby | OpenSSL raw-key Ed25519 | 8/8 |
| Java | JDK-native Ed25519, no third-party crypto | 8/8 |
| Rust | ed25519-dalek 2 | 8/8 |
| C#/.NET | BouncyCastle (no native Ed25519 in .NET) | 8/8 |

The Python and Node runners are the set's own and check all 19 in-set assertions, including the
invariants. The six added runners check the 8 signature-and-anchor assertions, 4 verifications
plus 4 anchor recomputations. That asymmetry is why the table reports each honestly rather than
flattening both into one number.

## Invariants, confirmed empirically

- **I1** recanonicalising a decoded payload does not reproduce the signed-token anchor.
- **I2** the issuer-JWT anchor is disclosure-invariant, and the three forms are genuinely
  distinct: issuer JWT `98f1d108...`, presentation `4b1df247...`, issuance `3af3c0d9...`.
  Anchoring a presentation therefore yields a different value from anchoring the issuer JWT.
- **I3** every signed token verifies under the section 7.1 public key, in all eight
  implementations above.
- **I4** the canon-sensitive divergence in vector 006 is attributable to a `jcs_edge_v1` class
  case: its canonical bytes carry literal U+2028 (`e2 80 a8`, not the escaped form) and render
  `1.0` as integer `1`.

## Why deterministic keys matter here

The set uses the RFC 8032 section 7.1 Test 1 keypair, and EdDSA is deterministic, so a given
signing input always produces byte-identical compact JWS output. Anyone can regenerate the exact
tokens and anchors rather than taking these values on trust. `generate.py` reproduces
`jws_anchor_v1.json` byte-for-byte.

## Reproduction

```bash
# JCS side, any of the ten runners
python derive_jcs_side.py                       # regenerates and self-checks the fixture
python runner_python.py jws_anchor_v1_jcs_side.json

# signature and anchoring side
go run sig_runner_go.go   ../../vectors/jws_anchor_v1/jws_anchor_v1.json
php sig_runner_php.php    ../../vectors/jws_anchor_v1/jws_anchor_v1.json
ruby sig_runner_ruby.rb   ../../vectors/jws_anchor_v1/jws_anchor_v1.json
```

Apache-2.0. Copyright 2026 AlgoVoi (chopmob@gmail.com).
