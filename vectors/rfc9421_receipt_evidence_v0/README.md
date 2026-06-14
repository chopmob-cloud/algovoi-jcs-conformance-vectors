# rfc9421_receipt_evidence_v0

**L2 receipt-evidence (key-source provenance) proposal set**, layered on top of the L1
signing-base reference [`rfc9421_proxy_chain_v1`](../rfc9421_proxy_chain_v1). The L1
RFC 9421 §2.5 message-signature result is **imported as a fixed anchor** (`signing_base_ref`)
and is never redefined here.

> Layer boundary (per [a2aproject/A2A#1829](https://github.com/a2aproject/A2A/issues/1829)):
> **L1** proves the *message* (the RFC 9421 §2.5 signing base). **L2** — this set — proves
> *how the signing key became acceptable* (key-source provenance). Same L1 signature,
> different verifier-evidence meaning depending on the key's trust posture.

## Status

- **Proposal set** — standalone, **not** part of the cross-validated JCS total (the 8-impl
  576). Reproducible offline from a single public library (`rfc8785`); no AlgoVoi code in the
  trust base.
- **License:** Apache-2.0 (same as the rest of this repository).
- Anchored to `draft-hopley-x402-canonicalisation-jcs-v1` (JCS RFC 8785, `jcs-rfc8785-v1`).

> **Attribution & stability.** This set imports the L1 base by hash (`signing_base_ref` /
> `signing_base_source_sha256`) and attributes it. That is the condition under which we keep an
> L2 layer stable: attributed L2 work is taken into account when L1 evolves; unattributed L2
> work is not, and continued interoperation is not guaranteed. See the corpus
> [README › Attribution](../../README.md#attribution) and [CHANGELOG](../../CHANGELOG.md).

## What it tests

Each vector is a receipt-evidence object that imports the L1 signature and declares a
`key_source` with its provenance. The conformance signal is the per-vector
`expected_jcs_bytes_b64` + `expected_content_hash` (RFC 8785 recompute), plus a verdict the
runner re-derives independently.

| Case | Vectors | Verdict | Why |
|---|---|---|---|
| `resolver_to_cache_valid` | `001-resolver-population-event`, `002-cache-with-population-ref` | conformant | resolver records the population event (url, allowlist policy, key digest, timestamp); the later cache row carries a `population_ref` pointing back to it by content hash |
| `cache_laundering_invalid` | `003-cache-laundering` | **non_conformant** | `key_source=cache` with no source, timestamp, or population digest — `CACHE_WITHOUT_POPULATION_EVENT` |
| `inline_pinned_valid` | `004-inline-pinned` | conformant | `key_source=inline` carries a pinned key digest and no network-resolution trust posture |
| `resolver_outside_allowlist_invalid` | `005-resolver-outside-allowlist` | **non_conformant** | `key_source=resolver` but `resolver_url` is not in the verifier's allowlist policy — `RESOLVER_OUTSIDE_ALLOWLIST` |
| `inline_unproven_invalid` | `006-inline-unproven` | **non_conformant** | `key_source=inline` with no `pinned_key_digest` or `origin_attestation` — a resolver-origin key relabeled inline — `INLINE_WITHOUT_ORIGIN_PROOF` |

### Conformance rules

Each `key_source` profile proves acceptability a different way; a bare label is never trusted:

- **`cache`** MUST carry `key_provenance.population_ref` (a `sha256:` pointer to a resolver
  population event). Absence → `CACHE_WITHOUT_POPULATION_EVENT`.
- **`resolver`** MUST have `resolver_url` in the **verifier-resolved** allowlist for its
  `allowlist_policy_id` (resolved from `policies` in the doc, never trusted from the receipt
  itself — the signer controlling the label cannot widen the allowlist). Absence →
  `RESOLVER_OUTSIDE_ALLOWLIST`.
- **`inline`** MUST carry `pinned_key_digest` or `origin_attestation`. A bare inline label is
  bypassable (a resolver-origin key relabeled inline). Absence → `INLINE_WITHOUT_ORIGIN_PROOF`.

Every invalid case produces a **non-conformant receipt**, not merely lower confidence. The
same L1 signature passes in all three profiles — what differs is whether the key-source
evidence explains why that key was acceptable at action time.

### Chain invariant

In `resolver_to_cache_valid`, row `002` `population_ref` equals row `001` `expected_content_hash`
— the cache entry traces back to its audited origin offline, with no access to the original
system.

## Run it

```
pip install rfc8785>=0.1.2
python runner_python.py     # recomputes JCS bytes + content hash, re-derives every verdict, checks the chain
python generate.py          # deterministically rewrites rfc9421_receipt_evidence_v0.json
```

Both the `rfc8785` reference library and AlgoVoi's own canonicaliser produce byte-identical
JCS bytes for every vector here, so the set is canonicaliser-independent.
