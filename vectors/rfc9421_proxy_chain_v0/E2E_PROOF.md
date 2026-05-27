# E2E Proxy-Chain Header Survival — Byte-Level Proof

**Date**: 2026-05-16
**Method**: Packet capture between proxy hops at the origin, verifying that the RFC 9421 and RFC 9530 headers reach the application server byte-for-byte unchanged after traversing a multi-hop proxy chain (edge CDN → reverse proxy → application server).

## Request Sent (client side)

```
GET https://api.algovoi.co.uk/compliance/attestation
Content-Digest: sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:
Signature-Input: sig=("@method" "@authority" "@path" "content-digest" "created");created=1778957126;keyid="did:web:api.algovoi.co.uk";alg="ed25519"
Signature: sig=:mFTiJpaYK2uSne18+cqnbAVeYrRxVTIN9v6tY3kLF5fMs9hfZXe2JqST15dZfVVeyGxn+29Tw4skXI49Z1vmAg==:
User-Agent: algovoi-proxy-chain-smoke-test
```

## Request Received at Application Server (captured at the origin)

```
GET /compliance/attestation HTTP/1.1
Content-Digest: sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:
User-Agent: algovoi-proxy-chain-smoke-test
Signature: sig=:mFTiJpaYK2uSne18+cqnbAVeYrRxVTIN9v6tY3kLF5fMs9hfZXe2JqST15dZfVVeyGxn+29Tw4skXI49Z1vmAg==:
Signature-Input: sig=("@method" "@authority" "@path" "content-digest" "created");created=1778957126;keyid="did:web:api.algovoi.co.uk";alg="ed25519"
```

## Result: Byte-Identical Header Survival

All three critical signature and digest headers arrived at the application server **byte-for-byte unchanged** after traversing the full 3-hop chain:

| Header | Sent | Received | Survived |
|--------|------|----------|----------|
| `Content-Digest` (RFC 9530) | `sha-256=:47DEQpj8...:` | `sha-256=:47DEQpj8...:` | yes |
| `Signature-Input` (RFC 9421) | `sig=("@method"...);keyid="did:web:api.algovoi.co.uk"` | same | yes |
| `Signature` (RFC 9421) | `sig=:mFTiJpaYK2u...:` | `sig=:mFTiJpaYK2u...:` | yes |

## Chain Traversed

```
Client
   ↓ TLS
Edge CDN (TLS termination, header pass-through)
   ↓ TLS (re-terminated at edge)
Reverse proxy at origin (TLS termination, header pass-through)
   ↓ HTTP plaintext on internal network
Application server
```

All three RFC 9421 / RFC 9530 headers were preserved unmodified across:

1. **TLS re-termination at the CDN edge** (no header rewriting)
2. **TLS re-termination at the origin reverse proxy** (no header stripping)
3. **HTTP plaintext hop within the internal network** (no edge proxy intervention)

This is empirical evidence that a correctly configured multi-hop proxy chain preserves RFC 9421 and RFC 9530 headers byte-for-byte, so a verifier downstream of the chain can re-derive and verify the signature without any per-hop accommodation.
