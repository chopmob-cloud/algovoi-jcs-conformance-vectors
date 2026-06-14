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
