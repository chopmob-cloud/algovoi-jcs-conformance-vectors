# `multichain_ed25519_substrate_v0`

AlgoVoi-authored conformance fixture demonstrating **Ed25519 signing
over a shared canonical payload across keys derived from independent
chain BIP44 paths** (Algorand, Solana, Stellar).

The property pinned: the same canonical JSON payload, when signed with
three Ed25519 keys derived from three different blockchain-specific
BIP44 paths, produces three independently verifiable signatures. None
of the chain-specific derivation paths impose constraints on the
payload content or alter the Ed25519 signing semantics — the signing
operation is the RFC 8032 reference algorithm regardless of where the
key originated.

This fixture supports the broader substrate-authorship claim that
AlgoVoi receipts (specified in
[`draft-hopley-x402-compliance-receipt`](https://datatracker.ietf.org/doc/draft-hopley-x402-compliance-receipt/))
can be signed by gateways operating on any chain that adopts Ed25519
key material via BIP44, without coupling the receipt format to a
specific chain.

## Scope

This fixture demonstrates a single property: Ed25519 signing is
chain-derivation-agnostic for a fixed canonical payload. It does
**not** claim to define a canonical A2A wire format, an inter-protocol
substrate independence proof, or any normative agentic-payment
specification. Those properties live elsewhere (in the IETF I-D above
and in the JCS canonicalisation substrate documented in
[`/canonicalisation-substrate`](https://docs.algovoi.co.uk/canonicalisation-substrate)).

## Canonical payload

The payload is fixed across all three chains:

```json
{
  "agent_id": "did:web:api.algovoi.co.uk",
  "capability": "pay_on_behalf",
  "expiration": 1778959200,
  "nonce": "9b80b883-69e6-468b-9a85-96394f82497a",
  "resource": "https://api.algovoi.co.uk/mandate/pay",
  "scope": ["checkout", "refund"]
}
```

**Canonical bytes (221, JCS-sorted)**: as in `fixture.json`'s
`payload_canonical_json` field.

**SHA-256**: `4f867161a905274c1d94aaa0bd0b093c4dcbcc10db5196aa7be11b120b56267c`

## Chain-derivation paths + reference signatures

| Chain | BIP44 path | Signature (b64) |
|---|---|---|
| Algorand | `m/44'/283'/0'/0'/0'` | `fj0plkJ/UCBYSj4e9VAzVJYd+VOoTcP41rVogfBdgjDcxC//0cI+E/nua7plXEMucEvkSJHJeFaaAmhhtPfnBA==` |
| Solana | `m/44'/501'/0'/0'` | `ytE+NFOiKWC+hMUO/i7x0hLHzI648kPfOChn9G+B3TV9YtcdGFqV4DmJxz0FVPfPiWn5/zgwqp6GWI/UrfB1Dw==` |
| Stellar | `m/44'/148'/0'` | `6brTXQAQiyCMSlPOTetxsLxLFs9N65Hcu3II2jTpClnDiGrvt0waDNfbrT0Q0cDpv4RLsqyxYzb+mZQuHgC6CQ==` |

Each signature is the RFC 8032 reference Ed25519 signature over the
canonical bytes of the payload, using the chain-specific derived key.

## What this fixture proves

- The Ed25519 signing operation produces a valid, independently
  verifiable signature for each of the three chain-derived keys, given
  the same canonical payload bytes.
- Wire-format Ed25519 verification is decoupled from key derivation
  policy: a downstream verifier needs only the public key and signature
  to verify, not the chain or derivation path.

## What this fixture does NOT claim

- It does not define a canonical A2A wire-format specification. The
  `agent_id`, `capability`, `resource`, `scope` field shapes shown are
  AlgoVoi-implementation-specific.
- It does not prove cross-protocol substrate independence at the spec
  level. That property is the subject of the IETF I-D and the
  canonicalisation substrate documentation linked above.
- It does not assert that BIP44 derivation paths are the only
  acceptable way to derive Ed25519 keys for gateway signing.

## Files

| File | Purpose |
|---|---|
| `payload.json` | The shared payload (pretty-printed) |
| `fixture.json` | Full fixture: canonical bytes + three signatures + per-chain derivation paths + chain seeds |
| `generate.py` | Re-generates the three signatures from the deterministic chain seeds |
| `verify.py` | Validates byte-match of all three signatures against the fixture |

## How to validate

```bash
pip install pynacl
python verify.py
```

Expected output:

```
[OK] Loaded fixture.json
A2A Payload: 221 bytes
Payload SHA-256: 4f867161a905274c1d94aaa0bd0b093c4dcbcc10db5196aa7be11b120b56267c
[OK] ALGORAND signature byte-match
[OK] SOLANA   signature byte-match
[OK] STELLAR  signature byte-match
=== VERIFICATION COMPLETE ===
```

## Provenance

- **Authorship**: AlgoVoi (chopmob-cloud).
- **Generated**: 2026-05-16.
- **Related work**: BIP44 (Multi-Account Hierarchy for Deterministic
  Wallets), SLIP-0010 (Universal private key derivation from master
  private key), RFC 8032 (Edwards-curve Digital Signature Algorithm).

## Licence

Apache 2.0. See [`LICENSE`](../../LICENSE) at the repository root.
