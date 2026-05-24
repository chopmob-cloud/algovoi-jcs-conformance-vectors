# algovoi-jcs-conformance-vectors

[![IETF I-D](https://img.shields.io/badge/IETF--I--D-draft--hopley--x402--compliance--receipt--00-blue)](https://datatracker.ietf.org/doc/draft-hopley-x402-compliance-receipt/)
[![Vectors](https://img.shields.io/badge/vectors-77-brightgreen)](#anchor-sets)
[![Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-green)](./LICENSE)

Conformance vector sets for JCS RFC 8785 canonicalisation across the
substrate anchor sets used by agentic-payment receipts. 77 vectors total,
cross-validated byte-for-byte across the substrate's reference implementations.

This repository is the AlgoVoi-authored reference test corpus that downstream
implementations of x402, AP2, A2A and MPP receipts can validate against. The
[`compliance_receipt_v1`](./vectors/compliance_receipt_v1/) anchor set is the
executable conformance test paired with IETF Internet-Draft
[`draft-hopley-x402-compliance-receipt-00`](https://datatracker.ietf.org/doc/draft-hopley-x402-compliance-receipt/)
(Independent Submission, Informational; posted 2026-05-23). The substrate
underneath is formalised in PR #2436 in `x402-foundation/x402` and pinned to
`urn:x402:canonicalisation:jcs-rfc8785-v1`.

## Anchor sets

| Anchor set | Vectors | What it exercises |
|---|---|---|
| [`vectors/ap2_omh_v0/`](./vectors/ap2_omh_v0/) | 7 | AP2 `open_mandate_hash` derivation — object-key-order, array-order, optional-fields, currency-minor-unit, Unicode NFC-vs-NFD pairs |
| [`vectors/ctef_aps_v1/`](./vectors/ctef_aps_v1/) | 14 | CTEF v0.3.1 + APS v1 envelope, verdict, scope-violation, composition-failure cases plus the APS attestation vector set |
| [`vectors/privacy_class_v0_1/`](./vectors/privacy_class_v0_1/) | 13 | Settlement-plane visibility declarations across the six privacy invariants in PR #2334 (privacy_class v0.1 supersedes v0) |
| [`vectors/per_chain_envelope_v0/`](./vectors/per_chain_envelope_v0/) | 19 | Per-chain receipt envelopes across seven chain families (Algorand, VOI, Hedera, Stellar, Base, Solana, Tempo) |
| [`vectors/action_ref_namespace_v0/`](./vectors/action_ref_namespace_v0/) | 8 | `action_ref` namespace-prefixing convention. Pins the four production-anchor digests (algovoi:compliance_screen, vauban:stark_settlement, agent_os:committed_claim, aura:reputation_observe) plus four unprefixed equivalents; 4 pair invariants prove the namespace prefix is byte-load-bearing. Validates against `algovoi-substrate>=0.2.1` on PyPI / `@algovoi/substrate>=0.2.1` on npm. |
| [`vectors/action_ref_transactional_v0/`](./vectors/action_ref_transactional_v0/) | 8 | Transactional `action_ref` lifecycle. Pins the byte-level invariants for multi-state transactional flows: `action_ref` stable across the lifecycle, `transition_hash` bound to its `action_ref`, state byte-load-bearing in the transition preimage. 5 pair invariants. Validates against `algovoi-substrate>=0.3.0` / `@algovoi/substrate>=0.3.0`. |
| [`vectors/compliance_receipt_v1/`](./vectors/compliance_receipt_v1/) | 8 | **Compliance receipt format**. Pins byte-level reference content hashes for the receipt format specified in IETF `draft-hopley-x402-compliance-receipt-00`. Three baseline receipts (ALLOW / REFER / DENY) demonstrating the closed enum is byte-load-bearing (incl. the POCA s.330 SAR-distinction); array-order probe; canon_version pin probe; three audit-chain rows demonstrating prev_hash linkage. 5 pair invariants + 3 chain invariants. Validates against `algovoi-substrate>=0.3.0`. |
| **Total** | **77** | |

## Cryptographic-property fixtures (complementary to JCS canonicalisation)

Two AlgoVoi-authored fixtures pin adjacent cryptographic properties of
the substrate that don't fit the JCS byte-determinism shape but
support the substrate authorship claim:

| Anchor set | Property | What it pins |
|---|---|---|
| [`vectors/rfc9421_proxy_chain_v0/`](./vectors/rfc9421_proxy_chain_v0/) | RFC 9421 HTTP message signature + RFC 9530 content-digest survive a 3-hop TLS-re-terminating proxy chain byte-identical | Single fixture using the RFC 8032 §7.1 Test 1 deterministic Ed25519 reference keypair. tcpdump wire-capture proof at `E2E_PROOF.md` |
| [`vectors/multichain_ed25519_substrate_v0/`](./vectors/multichain_ed25519_substrate_v0/) | Ed25519 signing over a shared canonical payload across keys derived from independent chain BIP44 paths (Algorand, Solana, Stellar) | Three signatures of the same 221-byte canonical JSON payload (SHA-256 `4f867161…0b56267c`) under three different chain-derivation paths |

## Cross-implementation validation matrix

The three IETF-I-D-anchored vector sets
([`action_ref_namespace_v0`](./vectors/action_ref_namespace_v0/),
[`action_ref_transactional_v0`](./vectors/action_ref_transactional_v0/),
[`compliance_receipt_v1`](./vectors/compliance_receipt_v1/)) have been
independently validated to produce byte-identical canonical bytes across
**eight independent JCS implementations in eight programming languages**,
all from non-overlapping authoring entities including the RFC 8785 author
himself (Anders Rundgren, via the Java implementation):

| # | Language | Package | Version | Author / entity |
|---|---|---|---|---|
| 1 | Python | `rfc8785` (via `algovoi-substrate`) | 0.1.4 | Trail of Bits |
| 2 | TypeScript / JS | `canonicalize` (via `@algovoi/substrate`) | 3.0.0 | Samuel Erdtman |
| 3 | Go | `gowebpki/jcs` | v1.0.1 | Web PKI Working Group |
| 4 | Rust | `serde_jcs` | 0.2.0 | seritalien / Vauban Pay |
| 5 | Java | `erdtman/java-json-canonicalization` | 1.1 | **Anders Rundgren** (RFC 8785 author) and Samuel Erdtman |
| 6 | PHP | `root23/php-json-canonicalization` | 1.0.1 | root23 (222K downloads on Packagist) |
| 7 | C# / .NET | `Baqhub.Packages.JsonCanonicalization` | 1.0.1 | Baqhub |
| 8 | Ruby | `json-canonicalization` | 1.0.0 | RubyGems community |

**Aggregate result: 192/192 byte-for-byte agreements** (24 vectors × 8
impls) on the 2026-05-24 attestation run. See
[`_attestations/2026-05-24-8-impl-cross-validation.md`](./_attestations/2026-05-24-8-impl-cross-validation.md)
for the full attestation record.

Per-anchor-set runner harnesses for Python and TypeScript ship alongside
each vector set (`runner_python.py`, `runner_node.js`); single-file
runners for the other six languages are AlgoVoi-authored and reproduce
the matrix from fresh installs of the packages above. The whole matrix
is reproducible by an independent third party in under thirty minutes of
package-install time, with no AlgoVoi infrastructure involved in any
validation step.

The broader corpus (the four earlier anchor sets covering AP2 OMH,
CTEF + APS, privacy_class, per-chain envelope) was validated against the
five-implementation matrix (Python, JS, Go, Java, Rust) at earlier dates
and remains in the same cross-impl byte-deterministic state.

## How to use this corpus

### As a downstream implementer

1. Pick the anchor set that matches your receipt type (AP2 mandates,
   CTEF / APS attestations, privacy_class declarations, per-chain envelopes).
2. Use one of the included runner harnesses against your implementation's
   canonicalisation routine.
3. If your bytes match the `expected_hash` for every vector in the set,
   your implementation is byte-for-byte conformant with the substrate.

### As a JCS implementation maintainer

The four anchor sets cover the JCS edge cases that show up in production
agentic-payment receipts and that synthetic conformance suites typically miss:

- Sub-100ms `timestamp_ms` integer values around retry windows.
- Integer-vs-float coercion at currency-minor-unit boundaries.
- Array element order divergence (`["UK","EU"]` vs `["EU","UK"]`).
- Unicode NFC vs NFD normalisation in mandate identifiers.
- Optional-fields presence vs absence in conformance pairs.

A JCS implementation that passes all 53 vectors is exercised against the
substrate's actual production failure modes, not only against synthetic
fixtures.

### As an AEOESS Consilium reviewer

The vectors are referenced in AEOESS Consilium Pass Candidate 5
(settlement-plane substrate matrix, AlgoVoi-authored, 2026-05-23). See the
substrate matrix at
<https://gist.github.com/chopmob-cloud/b327814c4e17ed9fc7b4f29c8bda523c>.

## Discipline rules tested

The substrate enforces these rules; the vectors exercise each:

- **Rule 1.** `timestamp_ms` is an epoch-millisecond integer.
- **Rule 3.** Field names are load-bearing opaque bytes.
- **Rule 4.** Type validation happens before canonicalisation.
- **`canon_version` pin.** Receipts carry `canon_version: "jcs-rfc8785-v1"`.
- **Array element order preserved.** RFC 8785 §3.2.3 ordering.

## Reference implementations

A reference implementation of the substrate primitives in Python and
TypeScript is shipped as `algovoi-substrate`:

- PyPI: <https://pypi.org/project/algovoi-substrate/>
- npm: <https://www.npmjs.com/package/@algovoi/substrate>
- Source: <https://github.com/chopmob-cloud/algovoi-substrate>

`pip install algovoi-substrate` or `npm install @algovoi/substrate` to get a
working canonicalize + action_ref + composite trust-query + compliance
receipt + audit chain implementation.

## Spec references

- [PR #2436](https://github.com/x402-foundation/x402/pull/2436) — canonicalisation discipline (three-voice coalition co-signed)
- [PR #2440](https://github.com/x402-foundation/x402/pull/2440) — composite trust-query
- [PR #2334](https://github.com/x402-foundation/x402/pull/2334) — privacy_class field
- [PR #2322](https://github.com/x402-foundation/x402/pull/2322) — Compliance category with `evidenceType`, `evidenceShape`, `anchor_chains` constraint
- [draft-vauban-x402-stark-receipts](https://datatracker.ietf.org/doc/draft-vauban-x402-stark-receipts/) — IETF I-D referencing the substrate

## Citing this corpus

When citing in a spec PR, paper, or implementation README, please use:

> AlgoVoi JCS Conformance Vectors v0.1, <https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors>, 2026-05-23. 53 vectors across four anchor sets, byte-for-byte cross-validated across Python `rfc8785`, JavaScript `canonicalize`, Go `gowebpki/jcs`, Java `cyberphone`, and Rust `serde_jcs`.

## Licence

Apache 2.0. See [`LICENSE`](./LICENSE).

## Author

AlgoVoi (Christopher Hopley, GitHub [`chopmob-cloud`](https://github.com/chopmob-cloud)). Per-anchor-set
contributor acknowledgements (Vauban Pay for Rust `serde_jcs` validation runs;
Agent OS for `did:agent-os` cross-chain identity vectors that compose against
the per-chain envelope set) are listed in each anchor set's README.
