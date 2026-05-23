# x402 `privacy_class` attestation conformance vectors (v0 + v0.1)

Conformance vector set for the `privacy_class` attestation digest used by the Bazaar registry's `JCS_hash` deduplication rule. Mirrors the [AP2 #265 open_mandate_hash paired-vector structure](https://gist.github.com/chopmob-cloud/1dca25fd6107db4b7a30bed5dbf2ded8) with the `timestamp_ms` lexical-pinning rule converged on across x402 [#2326](https://github.com/x402-foundation/x402/issues/2326) / [#2334](https://github.com/x402-foundation/x402/pull/2334) / [#2357](https://github.com/x402-foundation/x402/issues/2357).

## Versions

| Version | Vectors | Pair invariants | New since | File |
|---|---|---|---|---|
| **v0** | 10 | 9 | — | `privacy_class_v0.json    # or privacy_class_v0.1.json` |
| **v0.1** | 13 | 12 | field-name canonicalisation discipline (`007d`, `008a/008b`) per @Ilya0527 review on #2326 | `privacy_class_v0.1.json` |

**v0.1 is additive**: the 10 v0 vectors are byte-identical in v0.1. Implementations passing v0 also pass v0.1 for those 10 vectors. The 3 new v0.1 vectors test the new `field_name_canonicalisation` invariant. v0 artefact stays published unchanged — anyone pinned to v0 keeps their exact bytes; anyone moving to v0.1 picks up the field-name discipline coverage.

## Files

| File | Purpose |
|---|---|
| `privacy_class_v0.json    # or privacy_class_v0.1.json` | v0 artefact — 10 vectors, 9 pair invariants |
| `privacy_class_v0.1.json` | v0.1 artefact — superset: same 10 v0 vectors + 3 new field-name discipline vectors, 12 pair invariants |
| `runner_python.py` | Reference impl — `rfc8785` (Trail of Bits). Works on both versions: `python runner_python.py <artefact.json>` |
| `runner_node.js` | `canonicalize@3.0.0` (Erdtman; Rundgren as contributor) |
| `runner_go.go` | `gowebpki/jcs v1.0.1` |
| `RunnerJava.java` | `cyberphone/json-canonicalization` — Rundgren's Java reference cited in RFC 8785 |

## How `privacy_class_hash` is derived

```
privacy_class_hash := SHA-256( JCS(RFC 8785)( attestation body ) )
```

Canonicalisation MUST be applied AFTER schema normalisation — specifically:

- `timestamp_ms` is the canonical timestamp field (epoch integer, not RFC 3339 string)
- `effective_block_height` is the canonical block-height field (integer, not string)
- Unicode form is pinned at the schema layer (recommended: NFC)
- Arrays whose order is semantically meaningless MUST be sorted by the schema before canonicalisation

## Pair-invariant matrix

| # | Invariant | Pair | Expected | Version |
|---|---|---|---|---|
| 1 | object key order | sorted vs unsorted source | hash-identical (JCS sorts keys) | v0 |
| 2 | array order | preserve vs reorder | differs (JCS preserves array order) | v0 |
| 3 | optional field presence | present vs omitted | differs (presence ≠ absence) | v0 |
| 4 | scalar form (block height) | integer vs string | differs (JCS preserves scalar type) | v0 |
| 5 | Unicode normalisation | NFC vs NFD | differs (RFC 8785 does no Unicode normalisation) | v0 |
| 6 | timestamp lexical | `timestamp_ms` int vs RFC 3339 str vs RFC 3339 with `.000` | differs (different field names + different lexical forms) | v0 |
| **7** | **field-name canonicalisation** | **same value, different field name (`timestamp_ms` → `ts_ms`; `effective_block_height` → `block_no`)** | **differs (JCS treats field names as opaque)** | **v0.1** |

**Invariant #6** documents the failure mode that drove the #2357 convergence on `timestamp_ms` as the canonical preimage field. Vector 007a (`timestamp_ms` epoch integer) is the recommended canonical form; 007b and 007c demonstrate the divergences that occur when a producer emits RFC 3339 strings.

**Invariant #7** (v0.1) isolates field-name discipline from value-form discipline. Vector 007d-renamed-field uses field `ts_ms` with the *identical integer value* as 007a (`1747843200000`); the hash MUST differ from 007a even though the semantic value is identical, proving JCS preserves field names as opaque bytes and that schema field-name choice is itself a canonicalisation decision. Vector 008a/008b generalises the rule to a second field (`effective_block_height` vs `block_no` legacy L1 convention). Two pairs documenting one rule — matches the AP2 #265 structural discipline. Per @Ilya0527 review on #2326 (2026-05-21).

## Reproduce locally

### Python (reference)

```bash
pip install rfc8785==0.1.4
python runner_python.py privacy_class_v0.json    # or privacy_class_v0.1.json
```

### Node

```bash
npm install canonicalize@3.0.0
node --input-type=module runner_node.js privacy_class_v0.json    # or privacy_class_v0.1.json
```

### Go

```bash
go mod init privacy_class_runner && go get github.com/gowebpki/jcs@v1.0.1
go run runner_go.go privacy_class_v0.json    # or privacy_class_v0.1.json
```

### Java (Rundgren's reference impl)

```bash
git clone --depth 1 https://github.com/cyberphone/json-canonicalization.git
javac -d classes -sourcepath json-canonicalization/java/canonicalizer/src \
      json-canonicalization/java/canonicalizer/src/org/webpki/jcs/JsonCanonicalizer.java \
      RunnerJava.java
java -cp classes RunnerJava privacy_class_v0.json    # or privacy_class_v0.1.json
```

Each runner exits `0` iff every vector's recomputed SHA-256 matches `expected_privacy_class_hash` AND every pair expectation holds.

## Current cross-impl status

| Validator | Language | v0 (10 vec / 9 pairs) | v0.1 (13 vec / 12 pairs) |
|---|---|---|---|
| `rfc8785@0.1.4` | Python | 10/10 + 9/9 | 13/13 + 12/12 |
| `canonicalize@3.0.0` | JS | 10/10 + 9/9 | 13/13 + 12/12 |
| `gowebpki/jcs@v1.0.1` | Go | 10/10 + 9/9 | 13/13 + 12/12 |
| `cyberphone/json-canonicalization` | Java | 10/10 + 9/9 | 13/13 + 12/12 |

**v0**: 40 byte-for-byte agreements across four implementations / four languages / four non-overlapping author sets, including Anders Rundgren's Java reference impl cited in RFC 8785.

**v0.1**: 52 byte-for-byte agreements across the same four implementations. The 3 new field-name-discipline vectors produce identical hashes across all four impls, confirming JCS field-name handling is uniform across the reference impl set.

## Cross-reference with x402 #2398

[PR #2398 vector 0009 (`field-name-load-bearing`)](https://github.com/x402-foundation/x402/pull/2398) documents the same `timestamp` vs `timestamp_ms` divergence from the work-receipt layer. This set documents it from the attestation layer. Both surfaces of the same invariant.

— AlgoVoi (chopmob-cloud)
