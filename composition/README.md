<!--
  Apache-2.0. Copyright 2026 Christopher Hopley / AlgoVoi (chopmob-cloud).
  Part of the AlgoVoi agentic-payments substrate. Retain NOTICE on redistribution.
-->

# Verify It Yourself

### The complete agentic-payment substrate, proven end-to-end, offline, byte-for-byte, in one command.

[![offline](https://img.shields.io/badge/verification-100%25%20offline-brightgreen)](#how-verification-works)
[![byte-for-byte](https://img.shields.io/badge/24%20sets%20%2B%20lifecycle-byte--for--byte-brightgreen)](#the-full-corpus)
[![languages](https://img.shields.io/badge/cross--validated-8%20languages-brightgreen)](#why-you-can-trust-this)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](../LICENSE)

Most conformance suites prove that individual primitives hash correctly. This one
does that **and** proves the thing nobody else proves: that the entire regulated
agentic-payment lifecycle - identity, exactly-once settlement, attestation,
tamper-evident retention, and the final settlement-action binding - **composes
into a single self-verifiable chain**, where every link is a published
conformance output and the whole thing reproduces byte-for-byte with nothing but
SHA-256 and a JSON parser.

No servers. No accounts. No issuer callbacks. No trust in us. You run it, the
bytes match, and you are done.

---

## 30-second quickstart

All commands below run from the `composition/` directory:

```bash
git clone https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors
cd algovoi-jcs-conformance-vectors/composition
```

The core corpus and the composition keystone need only `algovoi-substrate`
(JCS + SHA-256, zero cryptographic dependencies):

```bash
pip install algovoi-substrate
python verify_corpus.py
```

That runs the 20 JCS+SHA-256 sets plus the end-to-end composition proof and exits
`0`. Four signature-bearing sets (Ed25519, Falcon-1024 PQC, RFC 9421) need extra
crypto libraries and are clearly flagged with their install command rather than
failing. For the full **24/24**, install the requirements first:

```bash
pip install -r requirements.txt
python verify_corpus.py
```

Exit code `0` means every canonical byte was reproduced on your machine.

```
sets: PASS=24  FAIL=0  schema-only=0   needs-deps=0   external=1   composition=PASS

ALL 24 RUN SETS + COMPOSITION KEYSTONE REPRODUCE BYTE-FOR-BYTE.
Your implementation is conformant with the AlgoVoi L1 substrate.
```

(With only `algovoi-substrate` installed you will see `PASS=20  needs-deps=4` and
still `exit 0` -- the core is conformant and the four signature sets tell you
exactly what to `pip install` for full coverage.)

---

## The keystone: the lifecycle actually composes

A regulated agentic payment is not one hash. It is a chain of obligations. The
substrate ships a primitive for each, and this proof shows they link into one
record - using **only already-published vectors**, introducing **no new vector
and no new hashing primitive**:

```
   action identity            action_ref            [action_ref_exactly_once_v1]
        |                                            MiCA Art 80  (stable identity)
        v
   exactly-once state         transition_hash       [action_ref_exactly_once_v1]
        |                      (COMMITTED)           DORA Art 14  (operational integrity)
        v
   settlement attestation     settlement_ref        [settlement_attestation_v1]
        |                      (content_hash)        AMLR Art 56  (settled payment retained)
        v
   tamper-evident chain       retention_chain_ref   [retention_chain_v1]
        |                                            MiCA 80 / DORA 14 (audit position)
        v
   settlement-action binding  binding_ref           [settlement_action_binding_v1]
                                                     all three (one bound record)
```

The proof is non-circular: the four inputs to `settlement_action_binding_v1` are
**byte-identical to the published `expected_*` outputs of the four upstream
sets**, and recomputing the binding from those composed values reproduces the
published reference exactly:

```
binding_ref = sha256:7dc4a2bf62b3c5eabd10fc875ff7fc10f188666f15838c4a51464cc72e80f6ca
```

Run just the keystone, in Python or Node (both produce the identical `binding_ref`):

```bash
python regulated_lifecycle_v1/verify_lifecycle.py
# or
cd regulated_lifecycle_v1 && npm install && node verify_lifecycle.mjs
```

It emits a human-readable trace and exits `0` on a 5/5 pass. The same chain is
captured as a deterministic evidence pack at
[`regulated_lifecycle_v1/lifecycle_trace.json`](./regulated_lifecycle_v1/lifecycle_trace.json) -
one file an auditor can read top to bottom and re-derive by hand.

---

## How verification works

Every offline check is the same two operations, and only these two:

1. **Canonicalize** the JSON preimage with JCS (RFC 8785) - deterministic key
   ordering and number/string encoding, so the bytes are identical on every
   platform and in every language.
2. **SHA-256** the canonical bytes.

That is the whole trust model. There is nothing to misconfigure, no key to hold,
no service to reach. If your bytes match the published bytes, you are conformant.
If they do not, you can see exactly which field diverged.

---

## The full corpus

`python verify_corpus.py` executes all of these in one pass. Each set carries its
own runner and its own published `expected_*` values; the umbrella simply runs
them and tallies the result.

| Set | What it proves |
| --- | --- |
| `action_ref_exactly_once_v1` | content-addressed action identity + exactly-once SKIP-on-retry |
| `action_ref_namespace_v0` | namespace prefix is byte-load-bearing |
| `action_ref_transactional_v0` | transactional lifecycle, state-bound transitions |
| `adversarial_isolation_v1` | adversarial inputs rejected at the validation layer |
| `ap2_omh_v0` | AP2 `open_mandate_hash` derivation (incl. Unicode NFC/NFD) |
| `cancellation_receipt_v1` | closed-enum cancellation receipts |
| `compliance_receipt_v1` | admission-time compliance receipt |
| `composite_trust_query_v1` | composite trust query envelope |
| `ctef_aps_v1` | CTEF / APS attestation vectors |
| `epi_interop_v0` | `.epi` portable evidence interop |
| `epi_pqc_v0` | `.epi` post-quantum profile |
| `multichain_ed25519_substrate_v0` | substrate-independent multichain wire format |
| `pef_v1` | Payment Evidence Frame: preimage + receipt + frame id |
| `per_chain_envelope_v0` | per-chain receipt envelopes (7 chain families) |
| `privacy_class_v0_1` | settlement-plane visibility declarations |
| `refund_receipt_v1` | refund receipts linked to a settled payment |
| `retention_chain_v0` | genesis + chain-link audit chain |
| `retention_chain_v1` | multi-issuer isolation + seq-gap adversarial pairs |
| `rfc9421_proxy_chain_v0` | RFC 9421 signing-base proxy chain |
| `rfc9421_proxy_chain_v1` | RFC 9421 Section 2.5 signing base |
| `rfc9421_receipt_evidence_v0` | RFC 9421 receipt evidence |
| `settlement_attestation_v1` | settlement attestation content hash |
| `settlement_action_binding_v1` | binds settlement to the verified action it paid for |
| `zkp_receipt_v1` | zero-knowledge receipt predicate |
| **`regulated_lifecycle_v1`** | **the keystone: all of the above, composed end-to-end** |

One set, `service_trust_v0`, is intentionally **outside** this offline corpus: it
is a third-party scoring set verified by calling an external service, not by local
SHA-256 + JCS. The umbrella reports it as `EXTERN` rather than pretending it is
offline. Honesty is part of the proof.

---

## Why an incompatible fork cannot pass

`action_ref` and `transition_hash` derive from **integer epoch-millisecond**
preimages (`timestamp_ms`, a non-negative integer). An implementation that admits
an RFC 3339 string timestamp instead computes a different `action_ref`, therefore
a different `transition_hash`, therefore a different `binding_ref`. It cannot
reproduce the bytes in this corpus.

This is not an argument we make in a comment thread. It is a property you can test
in one command. The adversarial vector `adv-001` in the lifecycle spec rejects the
RFC 3339 string explicitly, and the composition proof binds the consequence all
the way up to the settlement record. Conformance is decided by bytes, not by who
shouts loudest.

---

## Why you can trust this

- **Offline and deterministic.** No network, no clock, no randomness in any
  preimage. The same inputs always produce the same bytes.
- **Eight independent implementations.** The constructions are cross-validated
  byte-for-byte across Python, Node, Ruby, PHP, Go, Rust, Java, and .NET, against
  the same canonical bytes (for example the settlement-action binding set: 48/48,
  6 vectors x 8 languages). Independent re-derivation is the point.
- **Anchored, not invented.** The constructions are specified in the IETF
  Internet-Draft `draft-hopley-x402-retention-chain` and satisfy the recording and
  audit obligations of MiCA Article 80, DORA Article 14, and AMLR Article 56.
- **You verify, not us.** Nothing here asks you to trust AlgoVoi. It asks you to
  run SHA-256.

---

## L1 maintained, L2 supported

This corpus is the **L1 substrate**: open, stable, and maintained. If you are
building an L2 on top - a mandate lifecycle, a settlement flow, a receipt family,
an agent framework - these vectors are the tools that let you prove you are
byte-compatible with everyone else building on the same ground.

We maintain the L1 and we help you build the L2. The single condition is
attribution: keep the [`NOTICE`](../NOTICE) when you redistribute, and attributed
work is taken into account as the substrate evolves. That is the whole deal.

If you want help verifying your output against the canonical bytes, the offer is
genuine: chopmob@gmail.com.

---

## License and attribution

Everything here is licensed under the **Apache License, Version 2.0**
([`LICENSE`](../LICENSE)). Redistribution must retain the [`NOTICE`](../NOTICE)
per Section 4(d). Copyright 2026 Christopher Hopley / AlgoVoi (chopmob-cloud).
