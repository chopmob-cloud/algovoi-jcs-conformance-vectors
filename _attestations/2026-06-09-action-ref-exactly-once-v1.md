# 8-implementation cross-validation attestation -- action_ref_exactly_once_v1 -- 2026-06-09

This document attests the byte-for-byte cross-validation of the
**`action_ref_exactly_once_v1` exactly-once lifecycle vector set** across
**eight independent JCS RFC 8785 implementations in eight programming
languages** on 2026-06-09.

**Result: 48/48 byte-for-byte agreements.**

The set is a strict superset of `action_ref_transactional_v0`: the identical
`transition_hash` primitive, extended to the full exactly-once lifecycle
vocabulary **PENDING → COMMITTED → REVERSED**, and pinning the two load-bearing
exactly-once invariants — **SKIP-on-retry idempotency** (`same_hash_as`) and
**`action_ref` replay-binding** (`different_hash_from`).

## Vector set

| Field | Value |
|---|---|
| Vector set ID | `action_ref_exactly_once_v1` |
| Vectors | 6 |
| Pair invariants | 5 (incl. 1 `same_hash_as` idempotency) |
| Supersets | `action_ref_transactional_v0` |
| Canonicalisation pin | `jcs-rfc8785-v1` |
| Vector file | [`vectors/action_ref_exactly_once_v1/action_ref_exactly_once_v1.json`](../vectors/action_ref_exactly_once_v1/action_ref_exactly_once_v1.json) |

### Vectors

| Vector ID | state | digest |
|---|---|---|
| `action-ref-eo-v1-001` | identity | `7528529a8be2044488e603b7913efaa4f83620dbcc63010d4a1478cf7e9a473c` |
| `action-ref-eo-v1-002` | PENDING | `0957638b64c790292c11d90e9ae15576a6454f37f23a0aade222acf9e2ea18b0` |
| `action-ref-eo-v1-003` | COMMITTED | `f49faa7c4f82bd842705374311f5f6af073826539d519d0b65de3263258eac5f` |
| `action-ref-eo-v1-004` | REVERSED | `681a6026dbbac7555c46282eaf617d3f02560925ed8b44c31e3c854fcfc1f613` |
| `action-ref-eo-v1-005` | COMMITTED (retry of 003) | `f49faa7c4f82bd842705374311f5f6af073826539d519d0b65de3263258eac5f` (== 003) |
| `action-ref-eo-v1-006` | COMMITTED (different action_ref) | `97124ca25721d0aa31c8e30095d067c5bb1655ab10e573a08eb2f9d5f2c6a46d` |

## Implementations validated

| # | Runtime | Library | Version | Author |
|---|---|---|---|---|
| 1 | Python 3.12 | `rfc8785` (via `algovoi-substrate`) | 0.1.4 | Trail of Bits |
| 2 | Node.js v24 | `canonicalize` | 3.0.0 | Samuel Erdtman |
| 3 | Ruby 3.4 | `json-canonicalization` | 1.0.0 | RubyGems community |
| 4 | PHP 8.4 | inline pure-stdlib JCS RFC 8785 | -- | AlgoVoi (this attestation) |
| 5 | Go 1.26 | `gowebpki/jcs` | v1.0.1 | Web PKI Working Group |
| 6 | Rust 1.95 | `serde_jcs` | 0.2.0 | l1h3r |
| 7 | Java 17 | `io.github.erdtman:java-json-canonicalization` | 1.1 | Anders Rundgren (RFC 8785 author) + Samuel Erdtman |
| 8 | .NET 9 | `Baqhub.Packages.JsonCanonicalization` | 1.0.1 | Baqhub |

All eight implementations are by **non-overlapping authoring entities**,
including the RFC 8785 author himself (Anders Rundgren) via the Java
implementation.

## Full matrix

| Vector ID | Python | Node.js | Ruby | PHP | Go | Rust | Java | .NET | Row total |
|---|---|---|---|---|---|---|---|---|---|
| `action-ref-eo-v1-001` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | **8/8** |
| `action-ref-eo-v1-002` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | **8/8** |
| `action-ref-eo-v1-003` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | **8/8** |
| `action-ref-eo-v1-004` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | **8/8** |
| `action-ref-eo-v1-005` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | **8/8** |
| `action-ref-eo-v1-006` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | **8/8** |
| **Column total** | **6/6** | **6/6** | **6/6** | **6/6** | **6/6** | **6/6** | **6/6** | **6/6** | **48/48** |

## What this proves

1. **The exactly-once lifecycle is implementation-portable.** Every
   `transition_hash` across PENDING / COMMITTED / REVERSED reproduces
   byte-identical from eight independent runtime + library combinations.

2. **SKIP-on-retry idempotency is byte-exact.** Vector 005 re-presents a
   COMMITTED transition with an identical `(action_ref, state, timestamp)` tuple
   to 003 and reproduces 003's `transition_hash` **byte-for-byte in all eight
   languages** — a retry yields the same digest, never a second effect. This is
   the exactly-once guarantee, pinned as a cross-language invariant.

3. **`action_ref` replay-binding holds.** Vector 006 repeats 003's state and
   timestamps under a different `action_ref` and diverges in all eight
   implementations — a replay under another identity cannot collide.

4. **Clean superset of `action_ref_transactional_v0`.** No new primitive: the
   same five-field `transition_hash` preimage, the same identities. The two sets
   compose; this set extends the lifecycle vocabulary and adds the idempotency
   invariant.

## Combined attestation history

| Attestation | Vector sets | Implementations | Byte-for-byte agreements |
|---|---|---|---|
| 2026-05-24 | 3 (action_ref_namespace_v0, action_ref_transactional_v0, compliance_receipt_v1) | 8 | 192/192 |
| 2026-05-25 | 5 (compliance, settlement, cancellation, refund, composite-trust-query receipts) | 8 | 320/320 |
| 2026-05-30 | 1 (pef_v1) | 8 | 64/64 |
| **2026-06-09 (this)** | 1 (action_ref_exactly_once_v1) | 8 | **48/48** |
| **Cumulative direct** | 9 distinct vector sets | 8 distinct implementations | **624/624** |

## Provenance

- **Attestation date**: 2026-06-09
- **Reference implementations**: `algovoi-substrate>=0.3.0` (PyPI);
  `@algovoi/substrate>=0.3.0` (npm)
- **Canonicalisation discipline**: `jcs-rfc8785-v1`
- **Reproduction**:
  ```bash
  cd algovoi-jcs-conformance-vectors/_attestations/2026-06-09-action-ref-exactly-once-v1
  V=../../vectors/action_ref_exactly_once_v1/action_ref_exactly_once_v1.json
  python runner_python.py "$V"; node runner_node.js "$V"; ruby runner_ruby.rb "$V"; php runner_php.php "$V"
  go run runner_go.go "$V"
  (cd runner_rust && cargo +stable-x86_64-pc-windows-gnu run --release --quiet -- "$V")
  (cd runner_java && javac -cp "libs/*" Runner.java && java -cp ".;libs/*" Runner "$V")
  (cd runner_dotnet && dotnet run -c Release --verbosity quiet -- "$V")
  # each prints 6/6 PASS
  ```

## Licence

Apache 2.0. See [`LICENSE`](../LICENSE) at the repository root.
