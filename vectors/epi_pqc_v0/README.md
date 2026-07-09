# epi_pqc_v0

**Proposed** optional post-quantum signature profile for the `.epi` portable-evidence format
([microsoft/agent-governance-toolkit Discussion #806](https://github.com/microsoft/agent-governance-toolkit/discussions/806);
[epilabs.org](https://epilabs.org)). Companion to [`epi_interop_v0`](../epi_interop_v0): that set pins
the JCS canonicalisation `.epi` and AlgoVoi agree on byte-for-byte; **this set pins an optional
`falcon1024` signature suite and an F7 key-lineage continuity mechanism** on top of the same
canonicalisation.

> **Built on AlgoVoi's L1.** This PQC profile sits on the AlgoVoi L1 canonicalisation substrate
> (JCS RFC 8785, `draft-hopley-x402-canonicalisation-jcs-v1`). Same corpus rule — **build L2 freely;
> attribute the L1** (keep the [`NOTICE`](../../NOTICE), import by hash).

## Why

`.epi` is built for **decades-long** audit windows but seals artefacts with **classical Ed25519**.
Evidence that must remain verifiable across the post-quantum migration needs a post-quantum signature
and a way to validate a signature whose key was retired years ago. This set proposes:

- **`falcon1024` signature suite** — Falcon-1024 (NIST FIPS 206 FN-DSA) over the JCS bytes of the
  manifest, as `signature: "falcon1024:<kid>:<b64url-sig>"`. **Ed25519 stays the `.epi` default**; this
  is an opt-in suite — interop, not replacement.
- **key-lineage** — cross-signed rotation proofs (old key authorises new, new key counter-signs) so a
  verifier can confirm an artefact whose signing key was retired long ago.

It is **not** an adopted `.epi` suite — it is a proposal for the #806 conversation, published as a
citable fixture so multiple implementations can assert the same values.

## What it carries

- `vectors[]` — JCS canonicalisation vectors (same fields as `epi_interop_v0`: `id`, `input`,
  `canonical_preimage_spec`, `expected_jcs_bytes_b64`, `frame_id`, `timestamp_encoding`).
- `signature_suite_anchor` — a Falcon-1024 signature over the canonical manifest vector, with the
  public key + `kid`, so anyone can verify the suite offline.
- `key_lineage_anchor` — a 2-step (k1→k2→k3) cross-signed rotation lineage.

## Timestamp boundary (read this)

Inputs carry `.epi`-form **ISO-8601 string** timestamps. As with `epi_interop_v0`, this set pins the
**canonicalisation method** and the **falcon1024 signature recipe** — **not** substrate
integer-millisecond timestamp compliance (`draft-hopley-x402-canonicalisation-jcs-v1` §4.1). Each vector
declares its `timestamp_encoding`.

## Verify

```bash
pip install rfc8785>=0.1.2 pqcrypto>=0.4.0
python runner_python.py
```

Recomputes every `frame_id` from the input, verifies the Falcon-1024 signature anchor and the
key-lineage anchor against their published public keys, and asserts they match. No AlgoVoi code.

The JCS canonicalisation vectors (not the Falcon-1024 / key-lineage parts, which
are a separate cryptographic claim) are cross-validated across 10 independent
implementations (8 direct 2026-06-16, Elixir + Kotlin added 2026-07-09) via
`composition/generic_runner_elixir.exs` and `composition/GenericRunner.kt` — see
[`_attestations/2026-07-09-epi-elixir-kotlin.md`](../../_attestations/2026-07-09-epi-elixir-kotlin.md).
