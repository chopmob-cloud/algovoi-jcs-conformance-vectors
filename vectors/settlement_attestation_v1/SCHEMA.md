# settlement_attestation_v1 -- SCHEMA design + decision record

**Status**: design (pre-generation). Bytes-level reference hashes and the
public `README.md` are produced by `generate.py` once this schema is locked.

**Lifecycle position**: this format closes the gap between admission-time
compliance screening (`compliance_receipt_v1`) and post-settlement refunds
(`refund_receipt_v1`). The three formats together cover the full
agentic-payment receipt lifecycle:

```
admission -> settlement -> (optional) refund
compliance     settlement    refund
receipt        attestation    receipt
```

All three pin the same canonicalisation discipline
(`urn:x402:canonicalisation:jcs-rfc8785-v1`).

**Targeted IETF I-D**: `draft-hopley-x402-settlement-attestation-00`
(Independent Submission, Informational).

## Authorship

AlgoVoi-authored. This document, the receipt format it specifies, the
conformance vectors derived from it, and the reference implementations
that produce it are AlgoVoi work. AlgoVoi operates as an independent
substrate author as of 2026-05-24. Substrate authorship history is
catalogued at <https://docs.algovoi.co.uk/substrate-authorship-provenance>.

## Schema

The settlement attestation is an eight-field JSON object canonicalised
under RFC 8785 (JCS). Field names are sorted lexicographically by RFC 8785
during canonicalisation; the receipt object itself uses arbitrary
authoring order.

```json
{
  "canon_version": "jcs-rfc8785-v1",
  "jurisdiction_flags": ["UK", "EU"],
  "settled_payment_ref": "sha256:0dd5d0b76c9b9281fdeb2509ad38ab132b16a17385ca01d976ff9e6e12563a0f",
  "settlement_amount": {"amount_minor": "100000", "asset_id": "USDC.6"},
  "settlement_chain": "ethereum:8453",
  "settlement_provider_did": "did:web:api.algovoi.co.uk",
  "settlement_result": "SETTLED",
  "settlement_timestamp_ms": 1716494400000
}
```

### Field specifications

| Field | Type | Required | Description |
|---|---|---|---|
| `canon_version` | string | yes | In-band canonicalisation rule pin. Fixed `jcs-rfc8785-v1`. |
| `jurisdiction_flags` | ordered array of string | yes | ISO-3166-1 codes identifying applicable regulatory frameworks. **Array order is significant** under RFC 8785 §3.2.3. |
| `settled_payment_ref` | string | yes | Content-addressed reference to the original payment record (`sha256:<hex>`). When the original payment was admitted under a compliance receipt, conventionally equals the compliance receipt's `content_hash`. Same linkage discipline as `refund_receipt_v1.original_payment_ref`. |
| `settlement_amount` | object | yes | Two-field object: `{"amount_minor": string, "asset_id": string}`. Carries the settled value in the asset's minor unit. May differ from the original amount in cross-asset substitution cases (e.g. paid USDC on Base, settled USDC on Solana). |
| `settlement_chain` | string | yes | Identifies the chain on which settlement occurred. Convention: `<chain_family>` for default mainnet (e.g. `algo`, `solana`, `stellar`, `hedera`, `voi`); `<chain_family>:<network>` for non-default (e.g. `algorand:testnet`, `tempo:mainnet`, `ethereum:8453` for Base by chainId). |
| `settlement_provider_did` | string | yes | DID URI identifying the entity attesting settlement (gateway / facilitator / oracle). |
| `settlement_result` | string (closed enum) | yes | Closed three-element enumeration `{SETTLED, PENDING_FINALITY, REVERSED}`. See "Closed enumeration semantics" below. |
| `settlement_timestamp_ms` | integer | yes | Epoch milliseconds (UTC) of the settlement event. **Substrate Rule 2**: MUST be integer; RFC 3339 string forms rejected at validation time. |

### Closed enumeration semantics: `settlement_result`

The receipt format pins three categorical outcomes:

| Value | Semantic | Regulatory significance |
|---|---|---|
| `SETTLED` | Payment confirmed on-chain with sufficient finality for the operator's risk model. Funds transferred and irreversible under normal chain operation. | Triggers settlement-finality record-keeping obligations under MiCA Article 80 (Regulation (EU) 2023/1114) and AMLR Article 56 (Regulation (EU) 2024/1624). PSD2 (Directive 2015/2366) refund-window clock starts ticking from this point. |
| `PENDING_FINALITY` | Payment broadcast and included in a block, but awaiting the operator's required confirmation depth. Operator has visibility of inclusion but does not yet assert finality. | Under PSD2 (Directive 2015/2366) Article 89, the unauthorised-payment refund obligation has different timing relative to a PENDING vs SETTLED event. Recording this distinction enables operator audit trail under chain reorgs. |
| `REVERSED` | Payment was previously SETTLED but is now considered reversed (chain reorganisation, fraud reversal, double-spend resolution, or operator-initiated reversal under regulatory directive). The receipt records the reversal event so downstream refund / dispute / chargeback chains can reference it. | Triggers reversal-evidence obligations under AML-flagged transactions (POCA s.330, AML5/6) and creates a chain-of-custody record for chain-reorg adjudication. |

The three-element enumeration is byte-load-bearing under
canonicalisation: each value produces a byte-distinct `content_hash` from
the other two, preserving the regulatorily-significant distinction at the
canonical-bytes level rather than collapsing to a confidence score or
confirmation count.

A four-state extension including `BROADCAST_PENDING_INCLUSION` was
considered and rejected for v1: pre-inclusion state is an operational
detail at the gateway layer, not a regulatorily-load-bearing settlement
outcome.

A five-state extension including `EXPIRED` (payment broadcast but never
included before deadline) was considered and rejected: expiry without
inclusion does not produce a settlement event; the operator can record
this in operator-layer state without emitting a receipt under this format.

### Settlement chain identifier convention

`settlement_chain` is a string in one of two forms:

1. Default mainnet of a chain family: `<chain_family>`. Examples:
   - `algo` — Algorand mainnet
   - `voi` — VOI mainnet
   - `solana` — Solana mainnet
   - `stellar` — Stellar Pubnet
   - `hedera` — Hedera mainnet
   - `base` — Base L2 mainnet (alias for `ethereum:8453`)

2. Non-default network of a chain family: `<chain_family>:<network>`.
   Examples:
   - `algorand:testnet` — Algorand TestNet
   - `ethereum:1` — Ethereum mainnet
   - `ethereum:8453` — Base L2 (canonical by chainId)
   - `tempo:mainnet` — Tempo mainnet
   - `solana:devnet` — Solana devnet

The string is case-sensitive at the JCS layer; implementations SHOULD
canonicalise to lowercase before emission. Verifiers MUST treat
`Ethereum:8453` and `ethereum:8453` as distinct canonical bytes per
RFC 8785.

## Load-bearing invariants under RFC 8785

1. **`settlement_result` is a closed three-element enumeration and is
   byte-load-bearing.** Three otherwise-identical receipts varying only
   `settlement_result` MUST produce three byte-distinct `content_hash`
   values.

2. **`jurisdiction_flags` is ordered and byte-load-bearing.** Two
   otherwise-identical receipts varying only the array order MUST produce
   different `content_hash` values.

3. **`canon_version` is byte-load-bearing.** Two otherwise-identical
   receipts varying only `canon_version` MUST produce different
   `content_hash` values.

4. **`settlement_timestamp_ms` is integer-only.** Implementations MUST
   reject RFC 3339 string forms at validation time before
   canonicalisation. Substrate Rule 2.

5. **`settlement_amount` is a sub-object with stable field order under
   RFC 8785.** JCS sorts the sub-object's keys lexicographically:
   `amount_minor` then `asset_id`.

6. **`settled_payment_ref` is content-addressed.** The string
   `sha256:<hex>` prefix is part of the canonical bytes. Implementations
   MUST NOT strip the `sha256:` prefix during canonicalisation or
   verification.

7. **`settlement_chain` is a string identifier under JCS.**
   Implementations MUST NOT decompose the string into a sub-object during
   canonicalisation; the chain identifier is a single string field.

8. **Audit chain linkage.** Settlement attestations MAY participate in
   audit chains alongside compliance receipts and refund receipts. Chain
   row format follows the compliance-receipt audit chain (same row shape).

## Composition with other receipt classes

### compliance_receipt_v1 → settlement_attestation_v1

When a payment was admitted under a compliance receipt and subsequently
settled on-chain, the settlement attestation's `settled_payment_ref`
MAY equal the `content_hash` of the compliance receipt.

```
chain row N      chain row N+1
+------------+   +-------------+
| compliance |-->| settlement  |
| receipt    |   | attestation |
| (ALLOW)    |   | (SETTLED)   |
+------------+   +-------------+
```

### settlement_attestation_v1 → refund_receipt_v1

When a settled payment is subsequently refunded, the refund receipt's
`original_payment_ref` MAY equal the `content_hash` of the settlement
attestation rather than the original compliance receipt. This is useful
when the operator needs to record that "the settled-state payment was
later refunded" with a specific chain-of-custody trail.

```
chain row N+1    chain row N+2
+-------------+  +------------+
| settlement  |->| refund     |
| attestation |  | receipt    |
| (SETTLED)   |  | (FULL)     |
+-------------+  +------------+
```

### Full lifecycle chain

```
compliance receipt (ALLOW)
    |
    v   (settled_payment_ref)
settlement attestation (SETTLED)
    |
    v   (original_payment_ref)
refund receipt (FULL | PARTIAL | REJECTED)
```

A verifier walking the chain confirms the entire payment lifecycle from
admission through settlement to refund (or non-refund) under one
canonicalisation pin.

## Year-N auditability

Same five properties pinned by `draft-hopley-x402-compliance-receipt-00`
§6 apply to the settlement attestation:

1. Self-describing canonicalisation pin via `canon_version`.
2. No external rule registry required.
3. Cross-implementation verifiability under the same eight-impl JCS
   matrix that anchors the compliance receipt and refund receipt.
4. Tamper detection via per-row content_hash + prev_hash linkage.
5. Regulatory distinction preserved via the closed enumeration.

Plus one settlement-specific property:

6. **Chain-aware finality semantics.** The `settlement_chain` string
   identifies which chain's finality model applies. Verifiers reading
   the receipt years later can apply the correct chain-specific finality
   semantics (Algorand's deterministic instant finality, Ethereum's
   probabilistic depth-based finality, Stellar's SCP, etc.) to
   re-evaluate the original SETTLED claim.

## Conformance vectors planned

The `generate.py` script will produce 8 byte-level reference vectors:

| Vector | Group | What it pins |
|---|---|---|
| 001 | result-enum | SETTLED on Base (baseline) |
| 002 | result-enum | PENDING_FINALITY (otherwise identical to 001) |
| 003 | result-enum | REVERSED (otherwise identical to 001) |
| 004 | jurisdiction-order | `["EU","UK"]` vs 001's `["UK","EU"]` |
| 005 | canon-version-pin | `jcs-rfc8785-v2` probe |
| 006 | audit-chain-row | row 1 anchoring SETTLED (vector 001) |
| 007 | audit-chain-row | row 2 anchoring PENDING_FINALITY (vector 002) |
| 008 | audit-chain-row | row 3 anchoring REVERSED (vector 003) |

Plus 5 pair invariants and 3 chain invariants matching the compliance
receipt and refund receipt structures.

## Reference implementations planned

| Language | Package | New primitive |
|---|---|---|
| Python | `algovoi-settlement-attestation` (v0.1.0) | `build_settlement_attestation(...)` |
| TypeScript | `@algovoi/settlement-attestation` (v0.1.0) | `buildSettlementAttestation(...)` |

Both depend on `algovoi-substrate` / `@algovoi/substrate` for the JCS
canonicalisation primitive. Apache 2.0.

## What this schema is NOT

- **Not a cryptographic settlement proof.** `draft-vauban-x402-stark-receipts`
  by Vauban Pay covers cryptographically-strong post-quantum settlement
  proofs (Stwo Circle STARK over wire commitments). This format covers
  the categorical settlement outcome at the JCS canonicalisation layer
  and is composable with, not in competition with, cryptographic
  settlement proofs. Both can apply to the same payment event.
- **Not a chain-specific finality declaration.** The receipt records the
  attesting party's categorical outcome at a point in time. Chain-specific
  finality semantics (block depth, validator quorum, etc.) are out of
  scope; the operator MAY include them in operator-layer audit logs.
- **Not a cross-chain bridge proof.** When `settlement_amount.asset_id`
  differs from the original payment asset (cross-asset substitution),
  the equivalence-of-value claim is operator-layer and out of scope.
- **Not the only settlement-receipt format.** Other independent authors
  may publish settlement formats; this format specifies the
  AlgoVoi-discipline minimum byte-load-bearing surface required for
  cross-implementation verifiability under the canonicalisation pin.

## Licence

Apache 2.0.
