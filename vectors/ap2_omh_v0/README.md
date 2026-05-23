# AP2 `open_mandate_hash` v0 — conformance vectors + cross-impl runners

This gist hosts the **v0 conformance vector set** for AP2 `open_mandate_hash` and four runners that reproduce every vector byte-for-byte across four independent JCS (RFC 8785) implementations in four languages.

## Files

| File | Purpose |
|---|---|
| `ap2-omh-v0.json` | The artefact — 7 vectors, with `mandate_body`, `expected_jcs_bytes_b64`, `expected_open_mandate_hash`, and pair-invariant expectations. |
| `runner_python.py` | Reference impl — `rfc8785` (Trail of Bits) |
| `runner_node.js` | `canonicalize@3.0.0` (Erdtman; Rundgren as contributor) |
| `runner_go.go` | `gowebpki/jcs v1.0.1` |
| `JcsRunner.java` | `cyberphone/json-canonicalization` — Rundgren's Java reference cited in RFC 8785 |

## How `open_mandate_hash` is derived

```
open_mandate_hash := SHA-256( JCS(RFC 8785)( unsigned open-checkout-mandate body ) )
```

The hash input is the **mandate claims object**, not the JWS compact form. Re-encoding the JWS envelope must not change `open_mandate_hash`.

## Pair semantics

Each vector pair tests one canonicalization-edge invariant by construction:

| Invariant | Expected |
|---|---|
| object key order (sorted vs unsorted) | hash-identical (JCS sorts) |
| array order (preserve vs sort) | differs (JCS does not sort arrays) |
| optional field presence (null vs omitted) | differs (presence ≠ absence) |
| currency minor unit form | canonical integer minor units only |
| Unicode NFC vs NFD | differs (RFC 8785 performs no Unicode normalisation) |

## Reproduce locally

### Python (reference)

```bash
pip install rfc8785==0.1.4
python runner_python.py ap2-omh-v0.json
```

### Node

```bash
npm install canonicalize@3.0.0
node --input-type=module runner_node.js ap2-omh-v0.json
```

Or save `runner_node.js` next to a `package.json` with `"type": "module"`.

### Go

```bash
go mod init jcs_runner && go get github.com/gowebpki/jcs@v1.0.1
go run runner_go.go ap2-omh-v0.json
```

### Java (Rundgren's reference impl)

```bash
git clone --depth 1 https://github.com/cyberphone/json-canonicalization.git
javac -d classes -sourcepath json-canonicalization/java/canonicalizer/src \
      json-canonicalization/java/canonicalizer/src/org/webpki/jcs/JsonCanonicalizer.java \
      JcsRunner.java
java -cp classes JcsRunner ap2-omh-v0.json
```

All four runners exit `0` iff every vector's recomputed SHA-256 matches `expected_open_mandate_hash` and every pair invariant holds.

## Current cross-impl status

| Validator | Language | Result | Run by | Date |
|---|---|---|---|---|
| `rfc8785@0.1.4` | Python | 7/7 + 4/4 pair invariants | @chopmob-cloud | 2026-05-19 |
| `rfc8785@0.1.4` | Python | 7/7 + 4/4 pair invariants | @amavashev (independent) | 2026-05-19 |
| `canonicalize@3.0.0` | JS | 7/7 + 4/4 pair invariants | @chopmob-cloud | 2026-05-19 |
| `gowebpki/jcs@v1.0.1` | Go | 7/7 + 4/4 pair invariants | @amavashev (independent) | 2026-05-20 |
| `cyberphone/json-canonicalization` | Java | 7/7 + 4/4 pair invariants | @chopmob-cloud | 2026-05-20 |

The Python (#2) and Go (#4) runs are the independent third-party attestations (@amavashev). The JS and Java runs are self-run alongside the Python reference — they prove four-implementation library-determinism but are not third-party attestations. Independent re-runs of the Node and Java runners are welcomed.
