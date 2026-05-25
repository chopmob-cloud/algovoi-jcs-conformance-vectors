# `compliance_receipt_v1`

AlgoVoi-authored conformance vector set for the **compliance receipt format**
specified in IETF Internet-Draft
[`draft-hopley-x402-compliance-receipt`](https://datatracker.ietf.org/doc/draft-hopley-x402-compliance-receipt/)
(Independent Submission, Informational; submitted to the IETF datatracker
2026-05-23).

Pins byte-level reference digests for the receipt format, the closed
categorical enumeration, the canonicalisation discipline, and the
audit-chain linkage property so anyone implementing the I-D has runnable
test fixtures to validate their implementation.

## What this vector set proves

The compliance receipt is a six-field JSON object canonicalised under
RFC 8785 (JCS). Its `content_hash` is the SHA-256 of the canonical bytes:

```
content_hash = SHA-256(JCS(receipt))
```

The vector set pins eight byte-level reference vectors + five pair
invariants + three chain invariants to demonstrate the load-bearing
properties of the receipt format:

1. **The `screen_result` field is a closed three-element enumeration
   {ALLOW, REFER, DENY} and is byte-load-bearing.** Vectors 001 to 003
   are otherwise-identical receipts varying only `screen_result`. Pair
   invariants 001 to 003 assert all three pairwise digests differ. This
   is the load-bearing property under UK POCA 2002 Section 330: a REFER
   outcome can carry a Suspicious Activity Report obligation that a
   DENY does not, and the receipt format preserves the operational
   distinction at the canonical-bytes level rather than collapsing it
   to a score or tier projection.

2. **The `jurisdiction_flags` array is ordered and byte-load-bearing.**
   Vector 004 differs from vector 001 only in array order
   (`["EU","UK"]` vs `["UK","EU"]`) and pair invariant 004 asserts the
   digests differ. JCS RFC 8785 does not normalise array order.

3. **The `canon_version` pin is byte-load-bearing.** Vector 005 differs
   from vector 001 only in `canon_version` (`jcs-rfc8785-v2` vs
   `jcs-rfc8785-v1`) and pair invariant 005 asserts the digests differ.
   A receipt emitted under one canonicalisation-rule version cannot be
   silently re-hashed under a successor rule.

4. **Audit chain rows link via `prev_hash`.** Vectors 006, 007, 008 are
   the three rows of a hash-linked chain anchoring the receipts in
   vectors 001, 002, 003 respectively. Chain invariants 001 to 003
   assert: row 1's `prev_hash` is the all-zero anchor; row 2's
   `prev_hash` equals row 1's `row_content_hash`; row 3's `prev_hash`
   equals row 2's `row_content_hash`. A verifier walking the chain
   confirms linkage end-to-end.

Any implementation claiming conformance with
`draft-hopley-x402-compliance-receipt` at the canonical-bytes layer
MUST reproduce all eight `expected_content_hash` / `expected_row_content_hash`
values verbatim and MUST honour all five pair invariants and all three
chain invariants.

## Receipt content_hashes (vectors 001 to 005)

Fixed receipt fields across vectors 001 to 005:

```json
{
  "payer_ref": "sha256:0dd5d0b76c9b9281fdeb2509ad38ab132b16a17385ca01d976ff9e6e12563a0f",
  "screen_provider_did": "did:example:screening-provider-1",
  "screen_timestamp_ms": 1716494400000
}
```

| Vector | `screen_result` | `jurisdiction_flags` | `canon_version` | `expected_content_hash` |
|---|---|---|---|---|
| 001 | `ALLOW` | `["UK","EU"]` | `jcs-rfc8785-v1` | `9149cb61082765b556128d29926ccea3e2f3c17ba200b203f2f0a7d7c83e5f70` |
| 002 | `REFER` | `["UK","EU"]` | `jcs-rfc8785-v1` | `14638a6b0a2f2d73884be6ff0fc475901557d08b3fdee34c7703a6f7f259712a` |
| 003 | `DENY` | `["UK","EU"]` | `jcs-rfc8785-v1` | `843fd44b24cdec90fe829d7f0593c53fffa984dcdc389fbd1c4221a9623ded16` |
| 004 | `ALLOW` | `["EU","UK"]` | `jcs-rfc8785-v1` | `3c5f58374a084f1cac9861c26337912a1f1d3a9064d7a64fa825dea29efd01d1` |
| 005 | `ALLOW` | `["UK","EU"]` | `jcs-rfc8785-v2` | `4c0c0825c721c9589651bf5eb64517dfc55171466406823d0a0a72ca9658fde3` |

## Chain row_content_hashes (vectors 006 to 008)

Each chain row is `{prev_hash, receipt_content_hash, row_number}`. The
`row_content_hash` is `SHA-256(JCS(row))`.

| Vector | `row_number` | `prev_hash` (first 16 chars) | `receipt_content_hash` (first 16 chars) | `expected_row_content_hash` |
|---|---|---|---|---|
| 006 | 1 | `0000000000000000…` | `9149cb61082765b5…` | `a5589411e5e3feb582088dc69117aec706f852c1b3acaa8eadac8d919daf067d` |
| 007 | 2 | `a5589411e5e3feb5…` | `14638a6b0a2f2d73…` | `48ac027bef1501b105ea71fc2e67c9abdd10fef037ce49e2e05c3b1c00a1c6d4` |
| 008 | 3 | `48ac027bef1501b1…` | `843fd44b24cdec90…` | `bb3c3b0c103b0c5cb5508dcea56241f03a9129958b27553f7e5650a638577b78` |

## How to validate against this set

### Python

```bash
pip install algovoi-substrate>=0.3.0
python runner_python.py
```

### Node.js / TypeScript

```bash
npm install @algovoi/substrate@^0.3.0
node runner_node.js
```

Both runners load `compliance_receipt_v1.json`, canonicalise each
receipt (vectors 001 to 005) and each chain row (vectors 006 to 008),
compute SHA-256 of the canonical bytes, cross-check against the
substrate's `canonicalize` primitive, and verify all five pair invariants
and all three chain invariants. Output is one line per vector + one line
per invariant. Both runners expect to PASS all 16 checks
(8 vectors + 5 pair invariants + 3 chain invariants).

### Manual verification (any RFC 8785 impl)

1. For each receipt vector, take the `receipt` object verbatim.
2. Canonicalise under RFC 8785.
3. base64-encode the JCS bytes; MUST equal `expected_jcs_bytes_b64`.
4. SHA-256 the JCS bytes, lowercase hex; MUST equal `expected_content_hash`.
5. For chain row vectors, repeat steps 2 to 4 on the `row` object; the
   result MUST equal `expected_row_content_hash`.
6. Verify pair invariants: each `different_hash_from` pair MUST produce
   distinct digests.
7. Verify chain invariants: row 1 `prev_hash` is 64 zero hex; row 2
   `prev_hash` equals row 1 `row_content_hash`; row 3 `prev_hash`
   equals row 2 `row_content_hash`.

## Mapping to the IETF I-D

| Vector(s) | I-D anchor |
|---|---|
| 001 | Section 3 (Receipt Format Specification), Section 4 (Canonicalisation), Appendix A.1 |
| 002 | Section 3.2 (closed enumeration), Appendix A.2 |
| 003 | Section 3.2 (closed enumeration), Appendix A.3 |
| 004 | Section 3.5 (`jurisdiction_flags`, ordered) |
| 005 | Section 3.6 (`canon_version`, in-band rule pin) |
| 006 to 008 | Section 5 (Audit Chain Composition), Section 5.2 (Linkage Verification) |
| Pair 002 (REFER ≠ DENY) | Section 3.2 (POCA s.330 SAR-distinction example) |

## Provenance

- **Authorship**: AlgoVoi (chopmob-cloud). Specified in the IETF
  Internet-Draft cited above.
- **JSON Schema mirror**: the receipt format JSON Schema (draft-07) is
  published at [json.schemastore.org/algovoi-compliance-receipt-v1.json](https://json.schemastore.org/algovoi-compliance-receipt-v1.json)
  and mirrored in this repository at
  [`schemas/compliance-receipt-v1.schema.json`](../../schemas/compliance-receipt-v1.schema.json).
- **Reference implementations**:
  - Python: `algovoi-substrate>=0.3.0` on PyPI
  - TypeScript: `@algovoi/substrate>=0.3.0` on npm
- **Canonicalisation discipline**: `urn:x402:canonicalisation:jcs-rfc8785-v1`
  (see also the [Scope conventions](../action_ref_namespace_v0/) and
  [Transactional lifecycle](../action_ref_transactional_v0/) vector sets
  for the substrate-layer reference fixtures).
- **Cross-impl validation date**: 2026-05-23. Both reference impls
  produce byte-identical content hashes for all eight preimages.

## Licence

Apache 2.0. See [`LICENSE`](../../LICENSE) at the repository root.
