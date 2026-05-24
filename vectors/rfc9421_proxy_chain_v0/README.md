# `rfc9421_proxy_chain_v0`

AlgoVoi-authored conformance fixture for **RFC 9421 HTTP Message
Signatures + RFC 9530 Content-Digest survival through a multi-hop
proxy chain**.

Demonstrates that an RFC 9421-signed HTTP request retains byte-identical
`Signature-Input`, `Signature`, and `Content-Digest` headers after
traversing a three-hop proxy chain (Cloudflare edge → nginx reverse
proxy → FastAPI application server). The signature remains
independently verifiable at the application layer using only the public
key and the on-wire request bytes.

This fixture is part of the AlgoVoi conformance corpus paired with IETF
Internet-Draft
[`draft-hopley-x402-compliance-receipt-00`](https://datatracker.ietf.org/doc/draft-hopley-x402-compliance-receipt/);
the receipt format's audit-chain property assumes signed receipts can
be transported and re-verified independent of the originating gateway,
which is the property this fixture pins on the HTTP-signature layer.

## What this fixture proves

1. **RFC 9421 signature survives a 3-hop TLS-re-terminating proxy chain
   byte-identical.** `tcpdump` capture on the inner Docker network
   (between nginx and FastAPI) confirmed the same `Signature-Input`,
   `Signature`, and `Content-Digest` headers arrive at the application
   layer as were emitted by the client. See [`E2E_PROOF.md`](./E2E_PROOF.md)
   for the wire-capture record.

2. **The signature verifies cryptographically** using the test keypair
   from RFC 8032 Section 7.1 Test 1 (deterministic Ed25519 reference
   keypair, fully reproducible). The signing base follows RFC 9421
   Section 2.5 verbatim.

3. **Content-Digest matches** the (empty) request body per RFC 9530.

## Test vector

Uses RFC 8032 Section 7.1 Test 1 deterministic seed:

```
seed_hex       = 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
public_key_hex = d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
```

## Signing base (per RFC 9421 §2.5)

The covered components are `@method`, `@authority`, `@path`,
`content-digest`, plus the `created` timestamp. The signing base is
constructed exactly per RFC 9421:

```
"@method": get
"@authority": api.algovoi.co.uk
"@path": /compliance/attestation
"content-digest": sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:
"created": 1778955520
```

## Expected signature

```
Signature: sig=:Xj1peMjEYi75R/QQFYpU9q/gHwQKYwgt1etjAX1qc0zugTMJoJ86Uhy/jTZ175b3zFhp0j8cLjmDJvGmySDBAQ==:
```

A verifier running RFC 8032 Ed25519 signing over the signing base above
with the test keypair MUST produce this exact signature.

## Files

| File | Purpose |
|---|---|
| `request.fixture.json` | Signed GET request with RFC 9421 headers + signing-base reconstruction record |
| `response.fixture.json` | Real HTTP 200 response captured from the target endpoint |
| `chain.fixture.json` | Proxy-chain documentation (3 hops with role labels) |
| `generate.py` | Re-generates the signed request from the deterministic seed |
| `verify.py` | Validates signature byte-match + content-digest + endpoint reachability |
| `smoke_test.py` | End-to-end smoke test against the production endpoint |
| [`E2E_PROOF.md`](./E2E_PROOF.md) | `tcpdump` wire-capture record proving header survival on the inner network |

## How to validate

```bash
pip install pynacl
python verify.py
```

Expected output:

```
[OK] Loaded request.fixture.json
[OK] Loaded response.fixture.json
[OK] Test vector keypair matches RFC 8032 Section 7.1 Test 1
[OK] RFC 9530 content-digest verified (empty body)
[OK] Ed25519 signature byte-match verified
=== VERIFICATION COMPLETE ===
All fixture signatures and content-digests verified byte-match.
```

## Named target

The named production deployment used to capture the wire-survival
evidence is the AlgoVoi gateway at
`https://api.algovoi.co.uk/compliance/attestation`. Additional
deployments can be added as separate target rows alongside this one
without changing the underlying property the fixture demonstrates.

## Provenance

- **Authorship**: AlgoVoi (chopmob-cloud).
- **Generated**: 2026-05-16 (initial fixture + wire-capture proof).
- **Companion IETF I-D**:
  [`draft-hopley-x402-compliance-receipt-00`](https://datatracker.ietf.org/doc/draft-hopley-x402-compliance-receipt/)
  (Independent Submission, Informational; the receipt-format audit-chain
  property depends on the signed-receipt transport survival demonstrated
  here).
- **Related IETF documents**: RFC 9421 (HTTP Message Signatures),
  RFC 9530 (Digest Fields for HTTP), RFC 8032 (Edwards-curve Digital
  Signature Algorithm).

## Licence

Apache 2.0. See [`LICENSE`](../../LICENSE) at the repository root.
