# jws_anchor_v1

The signed-token **anchoring** conformance floor. Sibling to `jcs_edge_v1`, one layer up.

`jcs_edge_v1` pins the canonicalisation floor: given an object, the exact canonical
bytes. This set pins the layer above it: given a **signed** object, *which bytes an
implementation must hash when it anchors it*. That is the nastier failure, because
both parties can be perfectly JCS-conformant and still disagree on the anchor.

## What it pins

A verifier that anchors a signed receipt or mandate has three ways to get it wrong,
each of which produces a valid-looking anchor that binds the wrong thing:

- **Re-canonicalising the decoded payload.** Hashing `JCS(decoded payload)` instead
  of the signed bytes. The signature covers the compact JWS, not a re-serialisation,
  so `sha256(JCS(decoded))` is a different value and the anchor no longer binds the
  signed artifact. (`jws-anchor-002`.)
- **Anchoring a presentation instead of the issuer commitment.** An SD-JWT
  presentation carries a holder-selected subset of disclosures, so its bytes vary by
  disclosure. Only the issuer-signed JWT is disclosure-invariant, so that is the
  thing to anchor. (`jws-anchor-003` / `jws-anchor-004`.)
- **Confusing the two rules.** A signed token is anchored over its signed bytes; an
  *unsigned* object has no signed byte form and is anchored over `JCS(object)` (the
  `jcs_edge_v1` rule). (`jws-anchor-005`.)

`jws-anchor-006` ties the two sets together: it signs a payload with a `jcs_edge_v1`
case (a U+2028 string, the value `1.0`), so the signed-vs-recanonicalised divergence
happens *because of* the canonicalisation edge. The anchoring bug is worst exactly
where `jcs_edge_v1` lives.

## Reproducibility

Every token is signed with the **RFC 8032 section 7.1 Test 1** Ed25519 keypair (the
same deterministic key used in `rfc9421_proxy_chain_v0`):

    secret 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
    public d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a

EdDSA is deterministic, so every token and every anchor in `jws_anchor_v1.json` is
reproducible: `generate.py` regenerates the file byte-for-byte on any machine.
The file is pure ASCII.

## Contents

6 vectors, 4 invariants. Each vector carries its input (a compact JWS, an SD-JWT, or
a bare object) and the `expected_anchor` (`sha256:<hex>`). Negatives carry
`must_not_equal`. Invariants: I1 re-canonicalisation diverges from the signed anchor;
I2 the issuer-JWT anchor is disclosure-invariant while presentation and issuance are
not; I3 every signed token verifies under the section 7.1 public key; I4 the
canon-sensitive divergence is attributable to a `jcs_edge_v1` case.

Runners do not copy any value: they verify each signature, recompute each anchor from
the bytes, and compare.

## Run it

    pip install rfc8785 cryptography ; python runner_python.py
    npm install @algovoi/substrate ; node runner_node.js

## Licence

Apache-2.0 (see [LICENSE](./LICENSE)). Copyright 2026 AlgoVoi (chopmob@gmail.com).
Preserve the repository NOTICE attribution in any distribution.
