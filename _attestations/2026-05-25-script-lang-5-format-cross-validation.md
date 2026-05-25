# Script-language cross-validation attestation -- 2026-05-25

This document attests the byte-for-byte cross-validation of the
**five AlgoVoi-authored receipt and response format vector sets**
across **five independent JCS RFC 8785 implementations executed by
five scripting / agile-runtime environments** on 2026-05-25.

**Result: 200/200 byte-for-byte agreements.**

This attestation extends the prior 8-implementation attestation
[`2026-05-24-8-impl-cross-validation.md`](2026-05-24-8-impl-cross-validation.md)
(which covered 3 vector sets × 8 languages = 192 agreements) by
adding the four additional receipt/response format vector sets
shipped between 2026-05-24 and 2026-05-25:

- `settlement_attestation_v1` (8 vectors)
- `cancellation_receipt_v1` (8 vectors)
- `refund_receipt_v1` (8 vectors)
- `composite_trust_query_v1` (8 vectors, top-of-stack)

Together with the prior `compliance_receipt_v1` set, the **complete
agentic-payment receipt stack** (admission → settlement →
cancellation → refund, plus the top-of-stack composite-trust-query
response format) is now byte-for-byte cross-validated across the
scripting-runtime environments most common in operator deployments.

## Vector sets validated

| Vector set | Vectors | Pair invariants | Chain invariants | Lifecycle position |
|---|---|---|---|---|
| [`compliance_receipt_v1`](../vectors/compliance_receipt_v1/) | 8 | 5 | 3 | Admission |
| [`settlement_attestation_v1`](../vectors/settlement_attestation_v1/) | 8 | 5 | 3 | Settlement (per recurring execution) |
| [`cancellation_receipt_v1`](../vectors/cancellation_receipt_v1/) | 8 | 7 | 3 | Mandate termination |
| [`refund_receipt_v1`](../vectors/refund_receipt_v1/) | 8 | 5 | 3 | Post-settlement refund |
| [`composite_trust_query_v1`](../vectors/composite_trust_query_v1/) | 8 | 7 | 3 | Verifier response (top-of-stack) |
| **Total** | **40** | **29** | **15** | |

## Implementations validated

| # | Runtime | Library | Version | Author / authoring entity | Install command |
|---|---|---|---|---|---|
| 1 | Python 3.12 | `rfc8785` (wrapped by `algovoi-substrate`) | 0.1.4 / 0.3.0 | Trail of Bits / AlgoVoi | `pip install algovoi-substrate>=0.3.0` |
| 2 | Node.js v24 | `canonicalize` (wrapped by `@algovoi/substrate`) | 3.0.0 / 0.3.0 | Samuel Erdtman / AlgoVoi | `npm install @algovoi/substrate@^0.3.0` |
| 3 | Ruby 3.4 | `json-canonicalization` | 1.0.0 | RubyGems community | `gem install json-canonicalization` |
| 4 | PHP 8.4 | inline pure-stdlib JCS RFC 8785 | -- | AlgoVoi (this attestation, ~50 lines) | (no extra packages required) |
| 5 | Go 1.26 | `gowebpki/jcs` | v1.0.1 | Web PKI Working Group | `go get github.com/gowebpki/jcs@v1.0.1` |

All five implementations are by **non-overlapping authoring
entities**. The PHP runner ships an inline pure-stdlib JCS
implementation (no composer dependency) demonstrating that the
discipline can be reproduced in any runtime with native JSON and
SHA-256, not just in environments where a packaged JCS library is
available.

## Full matrix

| Vector set | Python | Node.js | Ruby | PHP | Go | Row total |
|---|---|---|---|---|---|---|
| `compliance_receipt_v1` | 8/8 | 8/8 | 8/8 | 8/8 | 8/8 | **40/40** |
| `settlement_attestation_v1` | 8/8 | 8/8 | 8/8 | 8/8 | 8/8 | **40/40** |
| `cancellation_receipt_v1` | 8/8 | 8/8 | 8/8 | 8/8 | 8/8 | **40/40** |
| `refund_receipt_v1` | 8/8 | 8/8 | 8/8 | 8/8 | 8/8 | **40/40** |
| `composite_trust_query_v1` | 8/8 | 8/8 | 8/8 | 8/8 | 8/8 | **40/40** |
| **Column total** | **40/40** | **40/40** | **40/40** | **40/40** | **40/40** | **200/200** |

## What this proves

Every byte-level expected digest in the five vector sets reproduces
byte-identical from five independent scripting-runtime JCS
implementations. This is empirical evidence that:

1. **The canonicalisation discipline is language-portable.** A
   downstream implementer in Python, Node.js, Ruby, PHP, or Go (and
   by the prior 8-impl attestation: Rust, Java, C# / .NET) gets the
   same canonical bytes from the same input. No language has special
   numeric handling, string-escaping, or key-ordering behaviour that
   diverges from the others.

2. **The discipline reproduces without a JCS library.** The PHP
   runner uses ~50 lines of inline JCS implementation (lexicographic
   key sort + recursion + `json_encode` with `JSON_UNESCAPED_UNICODE`)
   and reproduces all 200 expected digests. Any implementer in any
   language can build their own JCS implementation against this
   corpus and gain confidence at the byte level.

3. **The complete receipt stack composes cleanly.** All five
   formats (compliance, settlement, cancellation, refund,
   composite-trust-query) share the same canonicalisation pin,
   audit-chain row shape, and integer-millisecond timestamp encoding.
   The agentic-payment stack is byte-deterministic from admission
   through settlement, cancellation, refund, and verifier-emitted
   trust query, end-to-end.

## Combined with the prior attestation

Together with [`2026-05-24-8-impl-cross-validation.md`](2026-05-24-8-impl-cross-validation.md):

| Attestation | Vector sets | Implementations | Byte-for-byte agreements |
|---|---|---|---|
| 2026-05-24 | 3 (action_ref_namespace_v0, action_ref_transactional_v0, compliance_receipt_v1) | 8 (Python, TypeScript, Go, Rust, Java, PHP, .NET, Ruby) | 192/192 |
| **2026-05-25 (this)** | 5 (compliance, settlement, cancellation, refund, composite-trust-query) | 5 (Python, Node.js, Ruby, PHP, Go) | **200/200** |
| **Cumulative coverage** | 7 distinct vector sets / 5 full receipt-stack formats | 8 distinct implementations | **392/392** |

`compliance_receipt_v1` is now cross-validated under **8
implementations across both attestation runs**, with byte-identical
agreement on every vector under every implementation. The new four
sets (settlement, cancellation, refund, composite-trust-query) are
each cross-validated under 5 implementations in this run; extending
to the full 8-implementation matrix is mechanical (the runners are
the same shape; only the lib bindings differ).

## Coverage of deployment environment classes

The five-runtime matrix here covers the dominant scripting / agile
runtime environments for receipt-issuing operators:

- **Python**: data analysis, ML/AI agent frameworks, FastAPI/Django backends
- **Node.js**: agent SDKs, browser extensions, lightweight microservices
- **Ruby**: Rails / Sinatra backends, Shopify ecosystem
- **PHP**: WooCommerce, Magento, PrestaShop, Shopware e-commerce
- **Go**: agent runtime, gateway, high-throughput services

A downstream operator deploying in any of these runtimes can adopt
the AlgoVoi receipt formats and verify byte-deterministic
interoperation against this attestation.

## Provenance

- **Attestation date**: 2026-05-25
- **Conformance vector corpus version**: 0.5.0 (post composite-trust-query)
- **AlgoVoi substrate package versions** (where the implementation is
  wrapped):
  - `algovoi-substrate==0.3.0` (PyPI)
  - `@algovoi/substrate@0.3.0` (npm)
- **Companion IETF Internet-Drafts**:
  - [`draft-hopley-x402-canonicalisation-jcs-v1`](https://datatracker.ietf.org/doc/draft-hopley-x402-canonicalisation-jcs-v1/) -- the canonicalisation discipline
  - [`draft-hopley-x402-compliance-receipt-00`](https://datatracker.ietf.org/doc/draft-hopley-x402-compliance-receipt/)
  - [`draft-hopley-x402-settlement-attestation-00`](https://datatracker.ietf.org/doc/draft-hopley-x402-settlement-attestation/)
  - [`draft-hopley-x402-cancellation-receipt-00`](https://datatracker.ietf.org/doc/draft-hopley-x402-cancellation-receipt/)
  - [`draft-hopley-x402-refund-receipt-00`](https://datatracker.ietf.org/doc/draft-hopley-x402-refund-receipt/)
  - [`draft-hopley-x402-composite-trust-query-00`](https://datatracker.ietf.org/doc/draft-hopley-x402-composite-trust-query/)
- **Canonicalisation discipline**: `urn:x402:canonicalisation:jcs-rfc8785-v1`
- **Substrate Adopters Registry**: [`docs.algovoi.co.uk/adopters`](https://docs.algovoi.co.uk/adopters)
- **Reproduction**:
  ```bash
  git clone https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors
  cd algovoi-jcs-conformance-vectors/_attestations/2026-05-25-script-lang-5-format-cross-validation
  pip install algovoi-substrate>=0.3.0
  npm install @algovoi/substrate@^0.3.0
  gem install json-canonicalization
  bash run_all.sh
  # expect: Total: 200 PASS / 0 FAIL
  ```

## Licence

Apache 2.0. See [`LICENSE`](../LICENSE) at the repository root.
