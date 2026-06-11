# epi_interop_v0

Interop conformance set: AlgoVoi JCS canonicalisation cross-validated against
[EPI Recorder](https://github.com/mohdibrahimaiml/epi-recorder).

## What it is

EPI Recorder cross-tested its canonicalisation against this corpus, aligned its
`ensure_ascii` behaviour, and published a golden fixture
(`tests/compatibility/golden/canonical_hash_vectors.json`,
sha256 `205a911cbd984c0bbff2dce029db6d4b9220b398da646789c16a0b8f7aeaa34b`).
This set pins the five of those eight vectors whose `SHA-256(input)` reconciles
end-to-end with the AlgoVoi canonicaliser, as a shared, citable interop fixture.

Each vector carries:

| Field | Meaning |
|---|---|
| `id` | stable interop id (`interop-epi-NNN`) |
| `source_name` | the name in the EPI golden file |
| `input` | the verbatim input object |
| `canonical_preimage_spec` | the canonicalisation rule (JCS RFC 8785 then SHA-256, lowercase hex), citable to `draft-hopley-x402-canonicalisation-jcs-v1` |
| `expected_jcs_bytes_b64` | base64 of the RFC 8785 canonical bytes |
| `frame_id` | `sha256:` + SHA-256 of the canonical bytes |
| `timestamp_encoding` | the timestamp form actually present in `input` |

The `frame_id` is anchored to the I-D rather than either repo's HEAD, so both
implementations assert the same value from the same input.

## Timestamp boundary (read this)

These inputs carry EPI-form **ISO-8601 string** timestamps (or none). They are
**not** substrate-timestamp-compliant: the substrate requires integer-millisecond
timestamps and rejects RFC 3339 / ISO-8601 strings
(`draft-hopley-x402-canonicalisation-jcs-v1` section 4.1). This set pins the
**canonicalisation method** (where both implementations agree byte-for-byte),
not substrate timestamp compliance. Each vector declares its `timestamp_encoding`
so the boundary is explicit and testable. Substrate-native epoch-millisecond
variants may be added later as a separate labelled set.

## Verify

```
pip install rfc8785>=0.1.2
python runner_python.py
```

The runner recomputes `frame_id` and the JCS bytes from each `input` and asserts
they match the published values.

## Provenance

Cross-validation thread:
[microsoft/agent-governance-toolkit discussion 806](https://github.com/microsoft/agent-governance-toolkit/discussions/806).
The three omitted EPI vectors (`StepModel_source_type_excluded`,
`Nested_deep_content`, `Empty_collections_in_step`) are pending an
authoritative-column / `canonical_json` reconcile on the EPI side and will be
folded in once resolved.
