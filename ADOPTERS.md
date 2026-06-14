# Adopters — how to pin the AlgoVoi L1 substrate

Building an L2 layer (receipt-evidence, key-source provenance, settlement, …) on top of this
corpus? Here is how to pin the L1 base so the credit is **structural** and your layer is recorded
in the [change log](./CHANGELOG.md) — which doubles as the adopters list.

## 1. Pin the L1 by digest

In your L2 pack's manifest / imports block, reference the L1 signing-base by its **content hash**
— do not copy or redefine it:

```json
"imports": {
  "signing_base_set": "rfc9421_proxy_chain_v1",
  "signing_base_vector": "REQUEST",
  "signing_base_source_sha256": "7e5e8f1012eabd6aaae52b0ae4e77e4c8b0392077b620d2d944002a0531901e8",
  "note": "L1 result imported as a fixed anchor (signing_base_ref), not redefined here."
}
```

That digest is the L1 `REQUEST` fixture's SHA-256. Pinning it binds your layer to one exact,
immutable L1, and the pin is verifiable by anyone — the hash *is* the content, so it cannot be
forged or drift.

- Corpus version at time of writing: `manifest.json` `version: 0.7.1`, set `rfc9421_proxy_chain_v1`.
- Worked example: the `imports` block in
  [`vectors/rfc9421_receipt_evidence_v0/`](./vectors/rfc9421_receipt_evidence_v0/).

## 2. Keep the NOTICE

Retain the [`NOTICE`](./NOTICE) in your distribution (Apache-2.0 §4(d)). That is the attribution
the licence already asks for — keep it, and name the substrate you built on.

## 3. Get recorded

Once your manifest pins the digest, **open an issue** (or link your repo + commit). We verify two
things and nothing more:

1. the pinned digest matches the published L1 (content-addressed, so the check is exact), and
2. the `NOTICE` is present.

Then your layer is added to the **L2 layers** section of the [change log](./CHANGELOG.md).

## What gets recorded

Only attributed L2 is recorded. A layer that pins the digest **and** carries the `NOTICE` is a
recorded adopter; a layer that does neither is **not** entered, and future L1 changes are not
obliged to account for it. See [README › Attribution](./README.md#attribution).

The L2 design stays yours — we maintain L1, validate your layer against it, and keep the record.

## Recorded adopters

See the **L2 layers (validated against L1, recorded for change management)** section of the
[change log](./CHANGELOG.md). Be the first external pin — attribute the digest and open an issue.
