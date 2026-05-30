# x402 per-chain envelope conformance vectors v0

Per-chain canonicalisation conformance vector set covering JCS (RFC 8785) edge cases that surface at the **chain-identifier and chain-native-value layers** — distinct from the application-mandate layer (AP2 OMH v0) or the attestation layer (privacy_class). 19 vectors across 7 chain families, 9 declared pair invariants, validated across four reference JCS implementations.

## Files

| File | Purpose |
|---|---|
| `per_chain_envelope_v0.json` | The artefact — 19 vectors, `mandate_body` / `expected_jcs_bytes_b64` / `expected_per_chain_envelope_hash` / pair-invariant relations |
| `runner_python.py` | Reference impl — `rfc8785@0.1.4` (Trail of Bits) |
| `runner_node.js` | `canonicalize@3.0.0` (Erdtman; Rundgren contributor) |
| `runner_go.go` | `gowebpki/jcs v1.0.1` |
| `RunnerJava.java` | `cyberphone/json-canonicalization` — Rundgren's Java reference cited in RFC 8785 |

## Coverage

19 vectors across 7 chain families:

| Chain | Invariants tested | Vectors |
|---|---|---|
| **Algorand** | ASA-id scalar type; address canonical form | 3 |
| **VOI** | amount type (microunits int vs string) | 2 |
| **Hedera** | account/token-id lexical form; HTS allowance key-order | 3 |
| **Stellar** | SAC contract-id case sensitivity; 7-dp amount precision | 4 |
| **Base** (EVM) | EIP-55 checksum vs lowercase addresses | 2 |
| **Solana** | mint base58 case sensitivity; ATA vs wallet distinction | 3 |
| **Tempo** (EVM-derived L1) | EIP-55 checksum vs lowercase | 2 |

## How `per_chain_envelope_hash` is derived

```
per_chain_envelope_hash := SHA-256( JCS(RFC 8785)( mandate_body ) )
```

Same JCS + SHA-256 substrate as AP2 OMH v0, privacy_class v0/v0.1, CTEF/APS. The per-chain dimension stresses chain-specific scalar shapes, address-form canonicalisation, and chain-native amount precision rather than top-level mandate structure.

## Pair-invariant matrix

9 declared pair invariants, all passing across all four reference impls:

| # | Pair | Chain | Expected | Rationale |
|---|---|---|---|---|
| 1 | `algorand-001-asa-int` vs `algorand-002-asa-string` | Algorand | differs | JCS preserves scalar type — ASA-id as integer vs string-coerced |
| 2 | `voi-001-amount-int` vs `voi-002-amount-string` | VOI | differs | JCS preserves scalar type — microunits as int vs string |
| 3 | `hedera-002-hts-allowance-key-order` vs `hedera-003-hts-allowance-key-order-sorted` | Hedera | hash-identical | JCS sorts object keys; source key order is canonicalisation-invariant |
| 4 | `stellar-001-sac-uppercase` vs `stellar-002-sac-lowercase-issuer` | Stellar | differs | SAC contract-id case sensitivity preserved as opaque bytes |
| 5 | `stellar-003-7dp-trailing-zero` vs `stellar-004-7dp-no-trailing` | Stellar | differs | 7-dp amount precision — `"1.0000000"` vs `"1"` lexically distinct |
| 6 | `base-001-checksum-address` vs `base-002-lowercase-address` | Base (EVM) | differs | EIP-55 checksum address vs lowercase produces different bytes |
| 7 | `solana-001-mint-canonical` vs `solana-002-mint-lowercase` | Solana | differs | base58 case sensitivity preserved |
| 8 | `solana-001-mint-canonical` vs `solana-003-ata-vs-wallet` | Solana | differs | ATA (token account) vs wallet (owner) addresses are distinct |
| 9 | `tempo-001-checksum-address` vs `tempo-002-fully-lowercase` | Tempo | differs | EIP-55 checksum vs lowercase (EVM-derived L1) |

## Reproduce locally

### Python (reference)
```bash
pip install rfc8785==0.1.4
python runner_python.py per_chain_envelope_v0.json
```

### Node
```bash
npm install canonicalize@3.0.0
node --input-type=module runner_node.js per_chain_envelope_v0.json
```

### Go
```bash
go mod init per_chain_runner && go get github.com/gowebpki/jcs@v1.0.1
go run runner_go.go per_chain_envelope_v0.json
```

### Java (Rundgren's reference impl)
```bash
git clone --depth 1 https://github.com/cyberphone/json-canonicalization.git
javac -d classes -sourcepath json-canonicalization/java/canonicalizer/src \
      json-canonicalization/java/canonicalizer/src/org/webpki/jcs/JsonCanonicalizer.java \
      RunnerJava.java
java -cp classes RunnerJava per_chain_envelope_v0.json
```

Each runner exits `0` iff every vector's recomputed SHA-256 matches `expected_per_chain_envelope_hash` AND every pair-invariant relation holds.

## Cross-impl status

| Validator | Language | Result |
|---|---|---|
| `rfc8785@0.1.4` | Python | 19/19 + 9/9 pair invariants |
| `canonicalize@3.0.0` | JS | 19/19 + 9/9 pair invariants |
| `gowebpki/jcs v1.0.1` | Go | 19/19 + 9/9 pair invariants |
| `cyberphone/json-canonicalization` | Java | 19/19 + 9/9 pair invariants |

**76 byte-for-byte agreements** across four reference implementations / four languages / four non-overlapping author sets, including Anders Rundgren's Java reference impl cited in RFC 8785.

## Cross-references

- AP2 OMH v0: <https://gist.github.com/chopmob-cloud/1dca25fd6107db4b7a30bed5dbf2ded8>
- privacy_class v0 + v0.1: <https://gist.github.com/chopmob-cloud/30bcbc717c86493f737feb92c415ba07>
- CTEF + APS v1: <https://gist.github.com/chopmob-cloud/5f35eaa527d292bf3ddc52f8725a85c9>
- Coalition shared canonicalisation section: <https://github.com/x402-foundation/x402/issues/2326>

— AlgoVoi (chopmob-cloud)
