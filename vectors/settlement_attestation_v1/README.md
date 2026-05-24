# `settlement_attestation_v1`

AlgoVoi-authored conformance vector set for the **settlement attestation format**
specified in IETF Internet-Draft
[`draft-hopley-x402-settlement-attestation-00`](https://datatracker.ietf.org/doc/draft-hopley-x402-settlement-attestation/)
(Independent Submission, Informational; AlgoVoi-authored).

Lifecycle position: closes the gap between admission-time compliance
screening ([`compliance_receipt_v1`](../compliance_receipt_v1/)) and
post-settlement refunds ([`refund_receipt_v1`](../refund_receipt_v1/)).
The three formats together cover the full agentic-payment receipt
lifecycle:

```
admission         settlement        refund
compliance   -->  settlement   -->  refund
receipt           attestation       receipt
```

All three pin the same canonicalisation discipline
(`urn:x402:canonicalisation:jcs-rfc8785-v1`, normatively specified in
[`draft-hopley-x402-canonicalisation-jcs-v1`](https://datatracker.ietf.org/doc/draft-hopley-x402-canonicalisation-jcs-v1/)).

## What this vector set proves

The settlement attestation is an eight-field JSON object canonicalised
under RFC 8785 (JCS). Its `content_hash` is the SHA-256 of the
canonical bytes.

The vector set pins eight byte-level reference vectors + five pair
invariants + three chain invariants:

1. **`settlement_result` is a closed three-element enumeration
   {SETTLED, PENDING_FINALITY, REVERSED} and byte-load-bearing.**
   Each value produces a byte-distinct content_hash. Load-bearing
   under MiCA Art. 80 / AMLR Art. 56 record-keeping (SETTLED triggers
   finality records) and PSD2 Article 89 (PENDING vs SETTLED affect
   refund-window timing).

2. **`jurisdiction_flags` is ordered and byte-load-bearing.**

3. **`canon_version` is byte-load-bearing.**

4. **Audit chain rows link via `prev_hash`.**

## Receipt content_hashes

Fixed receipt fields across vectors 001 to 005:

```json
{
  "settled_payment_ref": "sha256:0dd5d0b76c9b9281fdeb2509ad38ab132b16a17385ca01d976ff9e6e12563a0f",
  "settlement_amount": {"amount_minor": "100000", "asset_id": "USDC.6"},
  "settlement_chain": "ethereum:8453",
  "settlement_provider_did": "did:example:settlement-provider-1",
  "settlement_timestamp_ms": 1716494400000
}
```

| Vector | `settlement_result` | `jurisdiction_flags` | `canon_version` | `expected_content_hash` |
|---|---|---|---|---|
| 001 | `SETTLED` | `["UK","EU"]` | `jcs-rfc8785-v1` | `0ead75bfe7fc74cc0421124903e56cb5c5006d02c393231a1d5f260fa87e96d3` |
| 002 | `PENDING_FINALITY` | `["UK","EU"]` | `jcs-rfc8785-v1` | `e7777a9a77a9c3f02339594395bfb2620e07edc62d3dcb48c4f2e82a8c37a1c4` |
| 003 | `REVERSED` | `["UK","EU"]` | `jcs-rfc8785-v1` | `4c5fed7ab1bcfb6cbb02599d52de034446582007dfe66f28e5a9b0715405c12e` |
| 004 | `SETTLED` | `["EU","UK"]` | `jcs-rfc8785-v1` | `e011a1c8b2481291c120518403c043424d12e048a78d5ef4d861192d0e7a5c5e` |
| 005 | `SETTLED` | `["UK","EU"]` | `jcs-rfc8785-v2` | `014dfcd6a2c364d749f3beaddfa6fa8a8433b171249760985cc0f3ae816afebd` |

## Audit chain row_content_hashes

| Vector | row_number | content_hash anchor | prev_hash | `expected_row_content_hash` |
|---|---|---|---|---|
| 006 | 1 | vector 001 (`SETTLED`) | 64 zero hex chars | `a4058baecb8c97476e391de102c745ee38f536effa957459fffc1354d6d658c7` |
| 007 | 2 | vector 002 (`PENDING_FINALITY`) | row 1's `row_content_hash` | `d7adf60c8833450ef9179a7dd1475937f909a564bbf6bf225396fce05eb00e1d` |
| 008 | 3 | vector 003 (`REVERSED`) | row 2's `row_content_hash` | `8d11bb5d54e856115a04745ff06855549d1750fdaf58e4bb14477c37c62c7dda` |

## Reference implementations

| Language | Package | How to run |
|---|---|---|
| Python | [`algovoi-settlement-attestation`](https://pypi.org/project/algovoi-settlement-attestation/) (>=0.1.0) | `pip install algovoi-settlement-attestation && python runner_python.py` |
| TypeScript | [`@algovoi/settlement-attestation`](https://www.npmjs.com/package/@algovoi/settlement-attestation) (>=0.1.0) | `npm install @algovoi/settlement-attestation && node runner_node.js` |

Both packages depend on `algovoi-substrate` / `@algovoi/substrate` for
the JCS canonicalisation primitive.

## Settlement chain identifier convention

`settlement_chain` is a string in one of two forms:

1. Default mainnet of a chain family: `<chain_family>` (e.g. `algo`,
   `voi`, `solana`, `stellar`, `hedera`, `base`)
2. Non-default network: `<chain_family>:<network>` (e.g.
   `algorand:testnet`, `ethereum:8453` for Base by chainId,
   `tempo:mainnet`, `solana:devnet`)

JCS canonicalises the string as opaque bytes; case is significant
under RFC 8785, so implementations SHOULD lowercase before emission.

## Composition with other receipt classes

A settlement attestation's `settled_payment_ref` MAY reference the
`content_hash` of a compliance receipt (per `compliance_receipt_v1`).
A refund receipt's `original_payment_ref` MAY reference the
`content_hash` of a settlement attestation. The full lifecycle
chain:

```
compliance receipt (ALLOW)
    |
    v   (settled_payment_ref)
settlement attestation (SETTLED)
    |
    v   (original_payment_ref)
refund receipt (FULL | PARTIAL | REJECTED)
```

A verifier walking this chain confirms admission → settlement →
refund under one canonicalisation pin.

## Authorship

AlgoVoi-authored. Substrate authorship history is catalogued at
<https://docs.algovoi.co.uk/substrate-authorship-provenance>.

## Licence

Apache 2.0.
