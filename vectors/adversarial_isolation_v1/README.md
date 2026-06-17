# `adversarial_isolation_v1`

AlgoVoi-authored **failure-isolation** conformance set for the substrate-1
primitives. Most conformance corpora are positive-only; this set leads on the
negative path — each vector is a valid canonical input with **one field
mutated**, isolating a single rejection. It pins not just *what canonicalises*
but *what must be rejected*, and exactly which check rejects it.

## Two separated claims (no overclaim)

Negative vectors are verifier-behaviour, not pure byte-convergence, so the set
carries **two distinct, separately-attested claims**:

- **Claim 1 — input bytes (8 languages).** Every `input` (control + mutated)
  canonicalises to its published `input_jcs_bytes_b64` / `input_content_sha256`
  **byte-for-byte across 8 independent RFC 8785 implementations**. The
  adversarial input is itself a real, reproducible JSON value that all
  implementations agree on — it is the *validation*, not the *canonicalisation*,
  that rejects it.
- **Claim 2 — rejection proof-of-rejection (reference impl).** The named
  substrate-1 check **raises** on every mutated input and **accepts** the
  control. Attested on the reference implementation only (`algovoi-substrate`
  Python + the substrate2 conformance gate). This is **explicitly NOT an 8-lang
  byte claim** — business-logic rejection is a property of the validator, not of
  JCS.

## Checks exercised (substrate-1, public)

| `check` | primitive | rejection type |
|---|---|---|
| `transition_preimage` | `substrate.transactional.transition_preimage` | `TransactionalError` |
| `action_ref` | `substrate.action.action_ref_object` | `ActionRefError` |
| `audit_chain` | `substrate.audit.verify_audit_chain` | `AuditChainError` |

## Vectors (12 — 1 control + 11 isolated rejections)

| vector_id | check | rejection code |
|---|---|---|
| `adv-v1-000-control` | transition_preimage | — (control: MUST be accepted) |
| `adv-v1-001-ts-rfc3339` | transition_preimage | `REJECT_NON_INT_TIMESTAMP` (RFC 3339 string where epoch-ms int required, Rule 2) |
| `adv-v1-002-ts-negative` | transition_preimage | `REJECT_NEGATIVE_TIMESTAMP` |
| `adv-v1-003-ts-bool` | transition_preimage | `REJECT_BOOL_TIMESTAMP` (bool is not an int) |
| `adv-v1-004-action-ref-nonhex` | transition_preimage | `REJECT_MALFORMED_ACTION_REF` (64 chars, not hex) |
| `adv-v1-005-action-ref-short` | transition_preimage | `REJECT_MALFORMED_ACTION_REF` (too short) |
| `adv-v1-006-state-empty` | transition_preimage | `REJECT_EMPTY_STATE` |
| `adv-v1-007-identity-ts-rfc3339` | action_ref | `REJECT_NON_INT_TIMESTAMP` (identity layer, Rule 1) |
| `adv-v1-008-identity-scope-empty` | action_ref | `REJECT_EMPTY_SCOPE` |
| `adv-v1-009-chain-prev-break` | audit_chain | `REJECT_PREV_HASH_BREAK` (linkage break) |
| `adv-v1-010-chain-content-mismatch` | audit_chain | `REJECT_CONTENT_HASH_MISMATCH` (stale content_hash) |
| `adv-v1-011-chain-wrong-position` | audit_chain | `REJECT_POSITION` |

The **control** is load-bearing: it proves the runner actually exercises the
check (a runner that rejects everything would "pass" all 11 rejects for the
wrong reason). The control must be *accepted*; every mutation must be *rejected*.

## How to validate against this set

### Claim 1 + Claim 2 (Python reference impl)
```bash
pip install algovoi-substrate>=0.3.0
python runner_python.py
```
Recomputes every `input`'s canonical bytes (Claim 1) and runs the named check,
asserting rejection of all 11 mutations and acceptance of the control (Claim 2).
Expect `Claim 1 12/12 ... Claim 2 12/12`.

### Claim 1 (any RFC 8785 impl)
Canonicalise each vector's `input`; base64 → MUST equal `input_jcs_bytes_b64`;
SHA-256 (lowercase hex) → MUST equal `input_content_sha256`. The 8-language
generic input-runners used for the attestation live in
[`_attestations/2026-06-09-adversarial-isolation-v1/`](../../_attestations/2026-06-09-adversarial-isolation-v1/).

`generate.py` regenerates this file deterministically (fixed inputs, no clock /
UUID / randomness).

## Cross-implementation validation (2026-06-09)

- **Claim 1:** 8 languages (Python, Node/TS, Ruby, PHP, Go, Rust, Java, .NET) ×
  12 inputs = **96/96 byte-for-byte**.
- **Claim 2:** **12/12** rejection/acceptance correct on the reference
  implementation (substrate2 conformance gate `reject-enforced` + runner_python).

See [`_attestations/2026-06-09-adversarial-isolation-v1.md`](../../_attestations/2026-06-09-adversarial-isolation-v1.md).

## Provenance

- **Authorship**: AlgoVoi (chopmob-cloud).
- **Normative anchor**: IETF Internet-Draft
  [`draft-hopley-x402-retention-chain-02`](https://datatracker.ietf.org/doc/draft-hopley-x402-retention-chain/)
  Sections 7.5 (Input Validation Rules) + 8.8 (Adversarial Boundary Vectors),
  17 June 2026.
- **Reference implementation**: Python `algovoi-substrate>=0.3.0` (PyPI). The
  reject enforcement is also wired into the substrate2 conformance gate
  (Section 1, `expectation: "reject"`): a reject vector that the check *accepts*,
  or that names no enforceable check, is a hard failure — never a silent skip.

## Licence

Apache 2.0. See [`LICENSE`](../../LICENSE) at the repository root.
