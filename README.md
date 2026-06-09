> **AlgoVoi is available for acquisition** — [docs.algovoi.co.uk/acquisition](https://docs.algovoi.co.uk/acquisition)

---

# algovoi-jcs-conformance-vectors

[![IETF I-D](https://img.shields.io/badge/IETF--I--D-draft--hopley--x402--compliance--receipt--00-blue)](https://datatracker.ietf.org/doc/draft-hopley-x402-compliance-receipt/)
[![Vectors](https://img.shields.io/badge/vectors-130-brightgreen)](#anchor-sets)
[![Cross-validated](https://img.shields.io/badge/cross--validated-576%2F576-brightgreen)](#cross-implementation-validation-matrix)
[![Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-green)](./LICENSE)

Conformance vector sets for JCS RFC 8785 canonicalisation across the
substrate anchor sets used by agentic-payment receipts. 130 vectors across
16 anchor sets, with **576/576 byte-for-byte agreements directly executed**
across eight independent JCS implementations in eight programming languages
(cumulative as of 2026-05-30; see the cross-implementation validation matrix).

This repository is the AlgoVoi-authored reference test corpus that downstream
implementations of x402, AP2, A2A and MPP receipts can validate against. The
[`compliance_receipt_v1`](./vectors/compliance_receipt_v1/) anchor set is the
executable conformance test paired with IETF Internet-Draft
[`draft-hopley-x402-compliance-receipt`](https://datatracker.ietf.org/doc/draft-hopley-x402-compliance-receipt/)
(Independent Submission, Informational; posted 2026-05-23). The substrate
underneath is formalised in PR #2436 in `x402-foundation/x402` and pinned to
`urn:x402:canonicalisation:jcs-rfc8785-v1`.

## Anchor sets

| Anchor set | Vectors | What it exercises |
|---|---|---|
| [`vectors/ap2_omh_v0/`](./vectors/ap2_omh_v0/) | 7 | AP2 `open_mandate_hash` derivation — object-key-order, array-order, optional-fields, currency-minor-unit, Unicode NFC-vs-NFD pairs |
| [`vectors/ctef_aps_v1/`](./vectors/ctef_aps_v1/) | 10 | CTEF v0.3.1 + APS v1 — the APS attestation vector set (`aps_vectors.json`). 4 further CTEF top-level cases (envelope / verdict / scope-violation / composition-failure) live in `ctef_vectors.json`. |
| [`vectors/privacy_class_v0_1/`](./vectors/privacy_class_v0_1/) | 13 | Settlement-plane visibility declarations across the six privacy invariants in PR #2334 (privacy_class v0.1 supersedes v0) |
| [`vectors/per_chain_envelope_v0/`](./vectors/per_chain_envelope_v0/) | 19 | Per-chain receipt envelopes across seven chain families (Algorand, VOI, Hedera, Stellar, Base, Solana, Tempo) |
| [`vectors/action_ref_namespace_v0/`](./vectors/action_ref_namespace_v0/) | 8 | `action_ref` namespace-prefixing convention. Pins the four production-anchor digests (algovoi:compliance_screen, vauban:stark_settlement, agent_os:committed_claim, aura:reputation_observe) plus four unprefixed equivalents; 4 pair invariants prove the namespace prefix is byte-load-bearing. Validates against `algovoi-substrate>=0.2.1` on PyPI / `@algovoi/substrate>=0.2.1` on npm. |
| [`vectors/action_ref_transactional_v0/`](./vectors/action_ref_transactional_v0/) | 8 | Transactional `action_ref` lifecycle. Pins the byte-level invariants for multi-state transactional flows: `action_ref` stable across the lifecycle, `transition_hash` bound to its `action_ref`, state byte-load-bearing in the transition preimage. 5 pair invariants. Validates against `algovoi-substrate>=0.3.0` / `@algovoi/substrate>=0.3.0`. |
| [`vectors/compliance_receipt_v1/`](./vectors/compliance_receipt_v1/) | 8 | **Compliance receipt format**. Pins byte-level reference content hashes for the receipt format specified in IETF `draft-hopley-x402-compliance-receipt`. Three baseline receipts (ALLOW / REFER / DENY) demonstrating the closed enum is byte-load-bearing (incl. the POCA s.330 SAR-distinction); array-order probe; canon_version pin probe; three audit-chain rows demonstrating prev_hash linkage. 5 pair invariants + 3 chain invariants. Validates against `algovoi-substrate>=0.3.0`. |
| [`vectors/settlement_attestation_v1/`](./vectors/settlement_attestation_v1/) | 8 | **Settlement attestation format**. Pins byte-level reference hashes for the post-settlement receipt format specified in IETF `draft-hopley-x402-settlement-attestation`. Covers SETTLED result, multi-chain settlement_chain values (algo / ethereum:84532 / solana / stellar / voi / tempo), audit-chain prev_hash linkage, settled_payment_ref content-addressing. 5 pair invariants + 3 chain invariants. |
| [`vectors/cancellation_receipt_v1/`](./vectors/cancellation_receipt_v1/) | 8 | **Cancellation receipt format**. Pins byte-level reference hashes for the mandate/checkout cancellation receipt format specified in IETF `draft-hopley-x402-cancellation-receipt`. Covers USER_REQUESTED / ADMIN / PAYMENT_FAILED cancellation reasons, mandate_ref content-addressing, audit-chain linkage. 7 pair invariants + 3 chain invariants. |
| [`vectors/refund_receipt_v1/`](./vectors/refund_receipt_v1/) | 8 | **Refund receipt format**. Pins byte-level reference hashes for the post-settlement refund receipt format specified in IETF `draft-hopley-x402-refund-receipt`. Covers FULL / PARTIAL refund_result enum, refund_amount sub-object canonicalisation, original_payment_ref content-addressing. 5 pair invariants + 3 chain invariants. |
| [`vectors/composite_trust_query_v1/`](./vectors/composite_trust_query_v1/) | 8 | **Composite trust-query response format**. Pins byte-level reference hashes for the top-of-stack verifier response format specified in IETF `draft-hopley-x402-composite-trust-query`. Covers TRUSTED / PROVISIONAL / INSUFFICIENT_EVIDENCE / UNTRUSTED trust_outcome enum, receipt_count field, evaluated_at timestamp. 7 pair invariants + 3 chain invariants. |
| [`vectors/pef_v1/`](./vectors/pef_v1/) | 8 | **Payment Evidence Frame v1**. Pins byte-level `frame_id` values for all five PEF claim types (`payment_admission`, `payment_settlement`, `payment_cancellation`, `payment_refund`, `composite_verdict`). Each vector validates two hashes: `sha256(JCS(receipt))` = `receipt_hash` and `sha256(JCS(preimage))` = `frame_id`. Normative spec: `draft-hopley-x402-payment-evidence-frame` (IETF I-D, filing pending). Reference implementations: [`algovoi-pef`](https://pypi.org/project/algovoi-pef/) (PyPI) / [`@algovoi/pef`](https://www.npmjs.com/package/@algovoi/pef) (npm). |
| [`vectors/zkp_receipt_v1/`](./vectors/zkp_receipt_v1/) | 8 | **ZKP receipt v1**. Canonical-bytes / `frame_id` vectors for the zero-knowledge settlement receipt across seven chains (Algorand, Base, Solana, VOI, Stellar, Hedera, Tempo). Companion to IACR ePrint 2026/109852. |
| [`vectors/service_trust_v0/`](./vectors/service_trust_v0/) | 5 | Service-trust check envelope (`urn:crest:trust-check-v1`) vectors. |
| **Total (JCS vectors, 14 sets)** | **126** | + 4 entries across the 2 cryptographic fixtures below = **130 vectors / 16 sets** |

## Cryptographic-property fixtures (complementary to JCS canonicalisation)

Two AlgoVoi-authored fixtures pin adjacent cryptographic properties of
the substrate that don't fit the JCS byte-determinism shape but
support the substrate authorship claim:

| Anchor set | Property | What it pins |
|---|---|---|
| [`vectors/rfc9421_proxy_chain_v0/`](./vectors/rfc9421_proxy_chain_v0/) | RFC 9421 HTTP message signature + RFC 9530 content-digest survive a 3-hop TLS-re-terminating proxy chain byte-identical | Single fixture using the RFC 8032 §7.1 Test 1 deterministic Ed25519 reference keypair. tcpdump wire-capture proof at `E2E_PROOF.md` |
| [`vectors/multichain_ed25519_substrate_v0/`](./vectors/multichain_ed25519_substrate_v0/) | Ed25519 signing over a shared canonical payload across keys derived from independent chain BIP44 paths (Algorand, Solana, Stellar) | Three signatures of the same 221-byte canonical JSON payload (SHA-256 `4f867161…0b56267c`) under three different chain-derivation paths |

## Cross-implementation validation matrix

The eight receipt-format / `action_ref` vector sets below were directly validated
to produce byte-identical canonical bytes across **eight independent JCS
implementations in eight programming languages** (576/576 agreements, cumulative
as of 2026-05-30), all from non-overlapping authoring entities including the
RFC 8785 author himself (Anders Rundgren, via the Java implementation). A ninth
set (`zkp_receipt_v1`, 2026-06-04) was directly executed across five of the eight
implementations and is reported separately below, not folded into the 576:

| # | Language | Runtime | Package | Version | Author / entity |
|---|---|---|---|---|---|
| 1 | Python | CPython 3.12 | [`rfc8785`](https://pypi.org/project/rfc8785/) | 0.1.4 | Trail of Bits |
| 2 | JavaScript | Node.js v24 | [`canonicalize`](https://www.npmjs.com/package/canonicalize) | 1.0.8 | Samuel Erdtman |
| 3 | Go | Go 1.26 | [`gowebpki/jcs`](https://github.com/gowebpki/jcs) | v1.0.1 | Web PKI Working Group |
| 4 | Rust | Rust 1.95 | [`serde_jcs`](https://crates.io/crates/serde_jcs) | 0.2.0 | l1h3r |
| 5 | Java | JDK 17 | [`erdtman/java-json-canonicalization`](https://github.com/erdtman/java-json-canonicalization) | 1.1 | **Anders Rundgren** (RFC 8785 author) and Samuel Erdtman |
| 6 | PHP | PHP 8.4 | inline pure-stdlib JCS (AlgoVoi-authored, ~50 lines) | -- | AlgoVoi |
| 7 | C# / .NET | .NET 9 | [`Baqhub.Packages.JsonCanonicalization`](https://www.nuget.org/packages/Baqhub.Packages.JsonCanonicalization) | 1.0.1 | Baqhub |
| 8 | Ruby | Ruby 3.4 | [`json-canonicalization`](https://rubygems.org/gems/json-canonicalization) | 1.0.0 | RubyGems community |

### Attestation history

| Date | Vector sets validated | Vectors x Impls | Result | Attestation |
|---|---|---|---|---|
| 2026-05-24 | `action_ref_namespace_v0`, `action_ref_transactional_v0`, `compliance_receipt_v1` | 24 × 8 | **192/192** | [`_attestations/2026-05-24-8-impl-cross-validation.md`](./_attestations/2026-05-24-8-impl-cross-validation.md) |
| 2026-05-25 | `compliance_receipt_v1`, `settlement_attestation_v1`, `cancellation_receipt_v1`, `refund_receipt_v1`, `composite_trust_query_v1` | 40 × 8 | **320/320** | [`_attestations/2026-05-25-8-impl-5-format-cross-validation.md`](./_attestations/2026-05-25-8-impl-5-format-cross-validation.md) |
| 2026-05-30 | `pef_v1` (PEF frame_id -- both `receipt_hash` and `frame_id` layers) | 8 × 8 | **64/64** | [`_attestations/2026-05-30-8-impl-pef-v1.md`](./_attestations/2026-05-30-8-impl-pef-v1.md) |
| **Cumulative (directly executed)** | **8 distinct vector sets** | **72 × 8** | **576/576** | |
| 2026-06-04 | `zkp_receipt_v1` (5 impls directly executed; remaining 3 asserted by transitivity — primitive-only payload covered by the 2026-05-25 run) | 8 × 5 direct | **40/40 direct** (+24 by transitivity, *not* added to the 576) | [`_attestations/2026-06-04-zkp-receipt-v1-cross-validation.md`](./_attestations/2026-06-04-zkp-receipt-v1-cross-validation.md) |

A separate signature-survival fixture, `rfc9421_proxy_chain_v0`, was validated **24/24** (8 implementations × 3 checks: signing-base + content-digest + Ed25519 verify) on 2026-05-24 ([attestation](./_attestations/2026-05-24-rfc9421-8-impl-cross-validation.md)); it is tracked apart from the JCS byte-agreement total.

### What the matrix covers

| Vector set | Claim / format | Layers validated per vector |
|---|---|---|
| `action_ref_namespace_v0` | `action_ref` namespace discipline | `sha256(JCS(action_ref))` |
| `action_ref_transactional_v0` | `action_ref` transactional lifecycle | `sha256(JCS(action_ref))` + `transition_hash` |
| `compliance_receipt_v1` | `compliance-receipt-v1` (payment_admission) | `sha256(JCS(receipt))` |
| `settlement_attestation_v1` | `settlement-attestation-v1` (payment_settlement) | `sha256(JCS(receipt))` |
| `cancellation_receipt_v1` | `cancellation-receipt-v1` (payment_cancellation) | `sha256(JCS(receipt))` |
| `refund_receipt_v1` | `refund-receipt-v1` (payment_refund) | `sha256(JCS(receipt))` |
| `composite_trust_query_v1` | `composite-trust-query-v1` (composite_verdict) | `sha256(JCS(receipt))` |
| `pef_v1` | PEF v1 frame_id -- all 5 claim types | `sha256(JCS(receipt))` **+** `sha256(JCS(preimage))` |

The `pef_v1` set is the only one that exercises two independent hash layers per
vector: the inner `receipt_hash` (identical discipline to the individual receipt
sets) and the outer `frame_id` (hash of the full PEF preimage). All 8 languages
reproduce both layers byte-identically.

Runner harnesses ship inside each attestation directory (`runner_python.py`,
`runner_node.js`, `runner_ruby.rb`, `runner_php.php`, `runner_go.go`,
`runner_rust/`, `runner_java/`, `runner_dotnet/`). The full matrix is
reproducible by an independent third party in under thirty minutes of
package-install time, with no AlgoVoi infrastructure involved in any validation
step.

## How to use this corpus

### As a downstream implementer

1. Pick the anchor set that matches your receipt type (AP2 mandates,
   CTEF / APS attestations, privacy_class declarations, per-chain envelopes).
2. Use one of the included runner harnesses against your implementation's
   canonicalisation routine.
3. If your bytes match the `expected_hash` for every vector in the set,
   your implementation is byte-for-byte conformant with the substrate.

### As a JCS implementation maintainer

These anchor sets cover the JCS edge cases that show up in production
agentic-payment receipts and that synthetic conformance suites typically miss:

- Sub-100ms `timestamp_ms` integer values around retry windows.
- Integer-vs-float coercion at currency-minor-unit boundaries.
- Array element order divergence (`["UK","EU"]` vs `["EU","UK"]`).
- Unicode NFC vs NFD normalisation in mandate identifiers.
- Optional-fields presence vs absence in conformance pairs.

A JCS implementation that passes all 126 JCS vectors is exercised against the
substrate's actual production failure modes, not only against synthetic
fixtures.

### As an AEOESS Consilium reviewer

The vectors are referenced in AEOESS Consilium Pass Candidate 5
(settlement-plane substrate matrix, AlgoVoi-authored, 2026-05-23). See the
substrate matrix at
<https://gist.github.com/chopmob-cloud/b327814c4e17ed9fc7b4f29c8bda523c>.

### As a developer — instant verification

Any of the `action_ref` vectors in this corpus can be verified against the
AlgoVoi production reference endpoint without installing anything:

```bash
curl -X POST https://verify.algovoi.co.uk/action-ref \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "did:web:api.algovoi.co.uk",
    "action_type": "algovoi:compliance_screen",
    "scope": "base:0xabc123",
    "timestamp_ms": 1748534400000
  }'
```

Returns the RFC 8785 JCS canonical form and SHA-256 digest. Verified
byte-identical across 8 independent implementations (see cross-implementation
validation matrix above).

## Discipline rules tested

The substrate enforces these rules; the vectors exercise each:

- **Rule 1.** `timestamp_ms` is an epoch-millisecond integer.
- **Rule 3.** Field names are load-bearing opaque bytes.
- **Rule 4.** Type validation happens before canonicalisation.
- **`canon_version` pin.** Receipts carry `canon_version: "jcs-rfc8785-v1"`.
- **Array element order preserved.** RFC 8785 §3.2.3 ordering.

## Reference implementations

### algovoi-substrate (canonicalisation primitives + receipt builders)

- PyPI: <https://pypi.org/project/algovoi-substrate/>
- npm: <https://www.npmjs.com/package/@algovoi/substrate>
- Source: <https://github.com/chopmob-cloud/algovoi-substrate>

`pip install algovoi-substrate` or `npm install @algovoi/substrate` for
canonicalize + action_ref + composite trust-query + compliance receipt +
audit chain implementation.

### algovoi-pef (Payment Evidence Frame)

The PEF v1 reference implementation -- wraps any AlgoVoi receipt in a
canonical frame with byte-deterministic `frame_id` and optional RFC 9421
signature field.

- PyPI: <https://pypi.org/project/algovoi-pef/>
- npm: <https://www.npmjs.com/package/@algovoi/pef>
- Source: <https://github.com/chopmob-cloud/algovoi-pef>

```python
from algovoi_pef import build_pef, verify_pef

frame = build_pef(
    claim_type="payment_admission",
    receipt=compliance_receipt_dict,
    frame_provider_did="did:web:api.algovoi.co.uk",
    frame_timestamp_ms=1748534600000,
)
assert verify_pef(frame)["valid"]
```

## Spec references

### IETF Internet-Drafts (AlgoVoi-authored)

- [`draft-hopley-x402-canonicalisation-jcs-v1`](https://datatracker.ietf.org/doc/draft-hopley-x402-canonicalisation-jcs-v1/) -- canonicalisation discipline. Specifies `urn:x402:canonicalisation:jcs-rfc8785-v1`.
- [`draft-hopley-x402-compliance-receipt`](https://datatracker.ietf.org/doc/draft-hopley-x402-compliance-receipt/) -- compliance-receipt-v1 (payment_admission)
- [`draft-hopley-x402-settlement-attestation`](https://datatracker.ietf.org/doc/draft-hopley-x402-settlement-attestation/) -- settlement-attestation-v1 (payment_settlement)
- [`draft-hopley-x402-cancellation-receipt`](https://datatracker.ietf.org/doc/draft-hopley-x402-cancellation-receipt/) -- cancellation-receipt-v1 (payment_cancellation)
- [`draft-hopley-x402-refund-receipt`](https://datatracker.ietf.org/doc/draft-hopley-x402-refund-receipt/) -- refund-receipt-v1 (payment_refund)
- [`draft-hopley-x402-composite-trust-query`](https://datatracker.ietf.org/doc/draft-hopley-x402-composite-trust-query/) -- composite-trust-query-v1 (composite_verdict)
- `draft-hopley-x402-payment-evidence-frame` -- PEF v1 (filing pending)

### x402-foundation/x402 upstream spec PRs (AlgoVoi-authored)

- [#2453](https://github.com/x402-foundation/x402/pull/2453) -- canonicalisation discipline (replaces [#2436](https://github.com/x402-foundation/x402/pull/2436))
- [#2493](https://github.com/x402-foundation/x402/pull/2493) -- compliance-receipt-v1
- [#2494](https://github.com/x402-foundation/x402/pull/2494) -- cancellation-receipt-v1 + refund-receipt-v1
- [#2495](https://github.com/x402-foundation/x402/pull/2495) -- pre-payment-compliance-gate-v1
- [#2524](https://github.com/x402-foundation/x402/pull/2524) -- settlement-attestation-v1
- [#2525](https://github.com/x402-foundation/x402/pull/2525) -- composite-trust-query-v1
- [#2526](https://github.com/x402-foundation/x402/pull/2526) -- rfc9421-x402-binding-v1
- [#2334](https://github.com/x402-foundation/x402/pull/2334) -- privacy_class field

### Other

- [docs.algovoi.co.uk/canonicalisation-substrate](https://docs.algovoi.co.uk/canonicalisation-substrate) -- v1 discipline reference
- [docs.algovoi.co.uk/canonicalisation-substrate-v2](https://docs.algovoi.co.uk/canonicalisation-substrate-v2) -- v2 (PQC-aware) additive successor
## Adopters

Parties pinning `canon_version: jcs-rfc8785-v1` in publicly-citable artefacts are recorded in the [Substrate Adopters Registry](https://docs.algovoi.co.uk/adopters). Current adopters:

- **AlgoVoi** — production gateway + reference implementations (this corpus + `algovoi-substrate` packages)
- **Supership / Crest Deployment Systems** — `service_trust_v0` vectors + `urn:crest:trust-check-v1` envelope at `verify.crestsystems.ai`
- **PEAC Protocol** — AP2 `open_mandate_hash` v0 fixture set ([peacprotocol/peac](https://github.com/peacprotocol/peac))

To request listing as an adopter, follow the [submission process](https://docs.algovoi.co.uk/adopters#how-to-submit-an-adoption-entry). AlgoVoi validates submissions against the artefact's canonical bytes and adds qualifying entries.

## Acknowledgments

This corpus and the AlgoVoi canonicalisation discipline it anchors are AlgoVoi-authored under sole authorship. The byte-for-byte cross-validation matrix is empirically possible only because of the independent JCS implementations maintained by other parties. AlgoVoi acknowledges with thanks:

**Reference JCS implementations cross-validated in the matrix** (576/576 byte-for-byte agreements across three attestation runs):

- Python [`rfc8785`](https://pypi.org/project/rfc8785/) 0.1.4 -- Trail of Bits
- JavaScript [`canonicalize`](https://www.npmjs.com/package/canonicalize) 1.0.8 -- Samuel Erdtman
- Go [`gowebpki/jcs`](https://github.com/gowebpki/jcs) v1.0.1 -- Web PKI Working Group
- Rust [`serde_jcs`](https://crates.io/crates/serde_jcs) 0.2.0 -- [l1h3r](https://github.com/l1h3r)
- Java [`erdtman/java-json-canonicalization`](https://github.com/erdtman/java-json-canonicalization) 1.1 -- **Anders Rundgren** (RFC 8785 / RFC 8032 author) and Samuel Erdtman
- PHP -- inline pure-stdlib JCS implementation (~50 lines, AlgoVoi-authored, no external dependency)
- .NET [`Baqhub.Packages.JsonCanonicalization`](https://www.nuget.org/packages/Baqhub.Packages.JsonCanonicalization) 1.0.1 -- [Baqhub](https://baqhub.io)
- Ruby [`json-canonicalization`](https://rubygems.org/gems/json-canonicalization) 1.0.0 -- RubyGems community

The discipline is validated by the editor of the canonicalisation standard it pins -- Anders Rundgren via the Java implementation -- and by six further independent implementations from non-overlapping authoring entities.

**Independent vector-set authors** (substrate-anchored vectors AlgoVoi cross-validated against the matrix):

- [@andysalvo](https://github.com/andysalvo) — work-binding vectors ([x402#2398](https://github.com/x402-foundation/x402/pull/2398))
- [feedoracle](https://github.com/feedoracle) (FeedOracle) — hybrid-PQC receipt-core vectors ([x402#2411](https://github.com/x402-foundation/x402/pull/2411))
- [arian-gogani](https://github.com/arian-gogani) (Nobulex) — bilateral-receipt vectors using the AlgoVoi `action_ref` derivation ([discussed on x402#2322](https://github.com/x402-foundation/x402/pull/2322))

**Discussion contributor:**

- [feedoracle](https://github.com/feedoracle) (FeedOracle) — proposed the retention-property scoping (MiCA Art. 80 / AMLR Art. 56 / DORA Art. 14) for the `canon_version` MUST clause; refined and incorporated into the discipline by AlgoVoi.

These roles describe validation, mirror, and discussion work relative to the AlgoVoi-authored discipline. They are not discipline co-authorship; see the [Version governance](https://docs.algovoi.co.uk/canonicalisation-substrate#version-governance) section. The substrate-author position rests on the byte-for-byte agreement these independent parties collectively confirm.

## Citing this corpus

When citing in a spec PR, paper, or implementation README, please use:

> AlgoVoi JCS Conformance Vectors, <https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors>, 2026-06-04. 130 vectors across 16 anchor sets, 576/576 byte-for-byte agreements directly executed across eight independent JCS implementations (Python `rfc8785`, JavaScript `canonicalize`, Ruby `json-canonicalization`, PHP inline, Go `gowebpki/jcs`, Rust `serde_jcs`, Java `erdtman/java-json-canonicalization`, .NET `Baqhub.Packages.JsonCanonicalization`), cumulative as of 2026-05-30.

## Licence

Apache 2.0. See [`LICENSE`](./LICENSE).

## Author

AlgoVoi (Christopher Hopley, GitHub [`chopmob-cloud`](https://github.com/chopmob-cloud)). Per-anchor-set
contributor acknowledgements (Vauban Pay for Rust `serde_jcs` validation runs;
Agent OS for `did:agent-os` cross-chain identity vectors that compose against
the per-chain envelope set) are listed in each anchor set's README.
## Attribution

This package is Apache-2.0. Use it freely and build whatever you are building on top of it. The only ask is the one the licence already makes: keep the NOTICE, and name who authored the substrate. To attribute it in your own product, add this to your NOTICE file:

```
This product includes the AlgoVoi substrate,
authored by Christopher Hopley / AlgoVoi (chopmob-cloud), Apache-2.0.
https://docs.algovoi.co.uk/canonicalisation-substrate
```

The full invitation is at https://docs.algovoi.co.uk/canonicalisation-substrate#adopt-the-substrate
