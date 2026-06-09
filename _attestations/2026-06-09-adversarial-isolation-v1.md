# Cross-validation attestation -- adversarial_isolation_v1 -- 2026-06-09

This document attests the **`adversarial_isolation_v1` failure-isolation vector
set**. Because negative vectors are verifier-behaviour rather than pure
byte-convergence, the set carries **two distinct, separately-attested claims**.
They are reported separately and **must not be conflated**.

- **Claim 1 — input bytes (8 languages): 96/96 byte-for-byte.**
- **Claim 2 — rejection proof-of-rejection (reference implementation): 12/12.**

## Vector set

| Field | Value |
|---|---|
| Vector set ID | `adversarial_isolation_v1` |
| Vectors | 12 (1 control + 11 isolated rejections) |
| Checks | `transition_preimage` (TransactionalError), `action_ref` (ActionRefError), `audit_chain` (AuditChainError) |
| Canonicalisation pin | `jcs-rfc8785-v1` |
| Vector file | [`vectors/adversarial_isolation_v1/adversarial_isolation_v1.json`](../vectors/adversarial_isolation_v1/adversarial_isolation_v1.json) |

## Claim 1 — input bytes (8 languages)

Every vector's `input` (the control and all 11 mutated inputs) canonicalises to
its published `input_jcs_bytes_b64` / `input_content_sha256` byte-for-byte across
eight independent JCS RFC 8785 implementations. The adversarial input is itself a
real, reproducible JSON value that all implementations agree on — it is the
*validation*, not the *canonicalisation*, that rejects it.

| Runtime | Library | Result |
|---|---|---|
| Python 3.12 | `rfc8785` 0.1.4 (via `algovoi-substrate`) | **12/12 PASS** |
| Node.js v24 | `canonicalize` 3.0.0 | **12/12 PASS** |
| Ruby 3.4 | `json-canonicalization` 1.0.0 | **12/12 PASS** |
| PHP 8.4 | inline pure-stdlib JCS RFC 8785 | **12/12 PASS** |
| Go 1.26 | `gowebpki/jcs` v1.0.1 | **12/12 PASS** |
| Rust 1.95 | `serde_jcs` 0.2.0 | **12/12 PASS** |
| Java 17 | `java-json-canonicalization` 1.1 (A. Rundgren) | **12/12 PASS** |
| .NET 9 | `Baqhub.Packages.JsonCanonicalization` 1.0.1 | **12/12 PASS** |

**Claim 1 total: 96/96 byte-for-byte.**

## Claim 2 — rejection proof-of-rejection (reference implementation only)

Business-logic rejection is a property of the validator, not of JCS, so this
claim is attested on the **reference implementation only** (`algovoi-substrate`
Python + the substrate2 conformance gate). It is **explicitly NOT an 8-language
byte claim.**

The named check `raise`s on each mutated input and **accepts** the control:

| Vector ID | check | expected | reference-impl result |
|---|---|---|---|
| `adv-v1-000-control` | transition_preimage | ACCEPT | accepted ✓ |
| `adv-v1-001-ts-rfc3339` | transition_preimage | `REJECT_NON_INT_TIMESTAMP` | TransactionalError ✓ |
| `adv-v1-002-ts-negative` | transition_preimage | `REJECT_NEGATIVE_TIMESTAMP` | TransactionalError ✓ |
| `adv-v1-003-ts-bool` | transition_preimage | `REJECT_BOOL_TIMESTAMP` | TransactionalError ✓ |
| `adv-v1-004-action-ref-nonhex` | transition_preimage | `REJECT_MALFORMED_ACTION_REF` | TransactionalError ✓ |
| `adv-v1-005-action-ref-short` | transition_preimage | `REJECT_MALFORMED_ACTION_REF` | TransactionalError ✓ |
| `adv-v1-006-state-empty` | transition_preimage | `REJECT_EMPTY_STATE` | TransactionalError ✓ |
| `adv-v1-007-identity-ts-rfc3339` | action_ref | `REJECT_NON_INT_TIMESTAMP` | ActionRefError ✓ |
| `adv-v1-008-identity-scope-empty` | action_ref | `REJECT_EMPTY_SCOPE` | ActionRefError ✓ |
| `adv-v1-009-chain-prev-break` | audit_chain | `REJECT_PREV_HASH_BREAK` | AuditChainError ✓ |
| `adv-v1-010-chain-content-mismatch` | audit_chain | `REJECT_CONTENT_HASH_MISMATCH` | AuditChainError ✓ |
| `adv-v1-011-chain-wrong-position` | audit_chain | `REJECT_POSITION` | AuditChainError ✓ |

**Claim 2 total: 12/12** (1 control accepted + 11 mutations rejected with the
correct error type).

The reject enforcement is also wired into the substrate2 conformance gate
(Section 1, `expectation: "reject"`): a reject vector the check *accepts*, or one
that names no enforceable check, is a hard failure — never a silent skip. A
deliberate false-green test (turning a reject vector's input valid while leaving
it marked `reject`) was confirmed to drop the gate from `11/11` to `10/11
reject-enforced` with an explicit failure, then restored on regeneration.

## What this proves

1. **Failure isolation is portable at the byte layer.** All adversarial inputs
   are canonical, reproducible objects (Claim 1) — they are not malformed JSON;
   they are well-formed inputs that the *substrate validation discipline*
   rejects.
2. **The reference implementation rejects exactly the right thing.** One
   isolated check per vector, the correct error type, and the control proves the
   runner genuinely exercises rejection (it is not rejecting everything).
3. **Honest scope.** The 8-language guarantee is the canonical-bytes layer
   (Claim 1). Rejection (Claim 2) is reference-impl behaviour, stated as such.

## Note on the cumulative byte total

Claim 1 contributes **96** byte-for-byte agreements on adversarial *inputs*.
These are recorded separately from the positive-vector cumulative; Claim 2
(rejection) is **not** a byte agreement and is **not** added to any byte total.

## Provenance

- **Attestation date**: 2026-06-09
- **Reference implementation**: `algovoi-substrate>=0.3.0` (PyPI)
- **Canonicalisation discipline**: `jcs-rfc8785-v1`
- **Reproduction**:
  ```bash
  cd algovoi-jcs-conformance-vectors
  # Claim 1 + Claim 2 (reference impl):
  (cd vectors/adversarial_isolation_v1 && pip install algovoi-substrate>=0.3.0 && python runner_python.py)
  # Claim 1 (8-language byte matrix):
  cd _attestations/2026-06-09-adversarial-isolation-v1
  V=../../vectors/adversarial_isolation_v1/adversarial_isolation_v1.json
  python runner_python.py "$V"; node runner_node.js "$V"; ruby runner_ruby.rb "$V"; php runner_php.php "$V"
  go run runner_go.go "$V"
  (cd runner_rust && cargo +stable-x86_64-pc-windows-gnu run --release --quiet -- "$V")
  (cd runner_java && javac -cp "libs/*" Runner.java && java -cp ".;libs/*" Runner "$V")
  (cd runner_dotnet && dotnet run -c Release --verbosity quiet -- "$V")
  # each prints 12/12 PASS
  ```

## Licence

Apache 2.0. See [`LICENSE`](../LICENSE) at the repository root.
