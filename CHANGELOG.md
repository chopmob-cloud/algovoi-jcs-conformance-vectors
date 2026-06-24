# Change log — AlgoVoi JCS Conformance Vectors

This corpus is an open L1 canonicalisation substrate (RFC 8785 JCS, anchored to
`draft-hopley-x402-canonicalisation-jcs-v1`, Apache-2.0). This file records changes to the L1
sets and the L2 layers validated against them.

## L1 attribution & L2 stability (policy)

**This change log records only attributed L2 developments.** We validate an L2 layer and enter
it here **only when the L1 base is attributed** (keep the NOTICE; import the L1 by hash via the
`signing_base_ref` / `signing_base_source_sha256` pattern). L2 work that does **not** attribute
the L1 base is **not recorded here and is not taken into account** when L1 evolves — its
continued interoperation is not guaranteed. Attributed L2 layers are first-class consumers: when
we evolve L1 we take them into account and weigh backward-compatibility for them. See the root
[README › Attribution](./README.md#attribution).

---

## L1 sets

- **17 anchor sets / 131 vectors**, 576/576 byte-for-byte agreements across eight independent
  JCS implementations (cumulative as of 2026-05-30). Latest L1 addition:
  `rfc9421_proxy_chain_v1` (RFC 9421 §2.5 signing base).
- **2026-06-18 — `settlement_action_binding_v1`** (6 vectors, 5 pair invariants). Post-settlement
  accountability binding: `binding_ref = "sha256:" + SHA-256(JCS({action_ref, transition_hash,
  settlement_ref, retention_chain_ref}))`. Composes `action_ref_exactly_once_v1`,
  `settlement_attestation_v1`, and `retention_chain_v1` — no new hashing primitive. Pins
  settlement-/action-/state-/chain-binding distinctness + stability. 8-lang cross-validated
  **48/48** (`_attestations/2026-06-18-settlement-action-binding-v1.md`). Reference impls:
  `algovoi-substrate` 0.4.0 / `@algovoi/substrate` 0.4.0 (`settlement_action_binding(...)`).
  Anchor: `draft-hopley-x402-retention-chain-02` §7 + `draft-hopley-x402-settlement-attestation-00`.
- **2026-06-24 — `settlement_binding_v1`** (composition; 6/6 links, Python == Node byte-for-byte).
  Execution-tier successor to `settlement_action_binding_v1`: a settlement attestation whose
  `settled_payment_ref` is the exact `execution_ref` the keystone produced (the settled payment
  binds to the executed action, not an identity), capped by one
  `execution_binding = "sha256:" + SHA-256(JCS({execution_ref, settlement_ref, retention_chain_ref}))`.
  Subsumes the old `(action_ref, transition_hash)` pair into one decision-bound reference. Composes
  `execution_ref_v1` / `keystone_v1`, `settlement_attestation_v1`, and the audit-chain row shape —
  no new hashing primitive. Reference impl: `algovoi-execution-ref` (`execution_binding(...)`).
  Anchor: `execution_ref` normative in `draft-hopley-x402-retention-chain-06` (§7.9, §7.10) +
  `draft-hopley-x402-settlement-attestation-00`.
- **2026-06-24 — `pef_keystone_v1`** (composition; 6/6 links, Python == Node byte-for-byte).
  PEF (Payment Evidence Frame) as the signed-transport layer over the keystone: a frame wraps the
  settlement-bound keystone record (the `execution_binding` output) verbatim, pins it with
  `receipt_hash = "sha256:" + SHA-256(JCS(receipt))`, and commits to it with
  `frame_id = "sha256:" + SHA-256(JCS(preimage))`. Tamper any carried keystone reference and both
  diverge. PEF is the envelope, not a new spine link. Reuses `execution_ref_v1` / `keystone_v1`,
  `settlement_binding_v1` (`binding_ref`), and the `pef_v1` frame construction byte-for-byte; the
  only schema change is the additive `claim_type` value `payment_execution` (preimage shape
  identical to `pef_v1`). Reference shape: `pef_v1`. Anchor: `payment-evidence-frame` +
  `draft-hopley-x402-retention-chain-06`.
- **2026-06-24 — `refund_execution_v1`** (composition; 5/5 links, Python == Node byte-for-byte).
  Refund anchored to the execution tier: a refund receipt whose `subject_ref` is the exact
  `execution_ref` the keystone produced (refund of the payment that committed, not just the
  decision). The anchor is byte-load-bearing (refund-over-execution differs from
  refund-over-decision; the latter matches the published `rf-001`). Reuses
  `refund_receipt_lite_v1` unchanged (subject_ref re-anchored) and `execution_ref_v1` /
  `keystone_v1`. Reference impl: `algovoi-refund-receipt-lite` (`refund_ref(...)`).

## L2 layers (validated against L1, recorded for change management)

L2 designs belong to the adopting ecosystem efforts that specify them. AlgoVoi's role is to
maintain the L1 substrate, **validate each L2 layer against the L1 anchor, and record it here**
for change management. These records are standalone, reproducible offline from `rfc8785`,
**not** part of the cross-validated L1 total. Each imports the L1 result as a fixed anchor and
attributes it.

- **`rfc9421_receipt_evidence_v0`** — validation record of the L2 receipt-evidence (key-source
  provenance) layer being specified at `a2aproject/A2A#1829` (the L2 design is that effort's;
  AlgoVoi validates + records, does not author it). Imports `rfc9421_proxy_chain_v1` REQUEST as
  `signing_base_ref`. **5 cases / 6 vectors**, all independently re-validated green
  (`runner_python.py`): `resolver_to_cache_valid`, `cache_laundering_invalid`
  (`CACHE_WITHOUT_POPULATION_EVENT`), `inline_pinned_valid`, `resolver_outside_allowlist_invalid`
  (`RESOLVER_OUTSIDE_ALLOWLIST`), `inline_unproven_invalid` (`INLINE_WITHOUT_ORIGIN_PROOF`).
  Same L1 signature passes in every key-source profile; what differs is whether the evidence
  explains why the key was acceptable.
