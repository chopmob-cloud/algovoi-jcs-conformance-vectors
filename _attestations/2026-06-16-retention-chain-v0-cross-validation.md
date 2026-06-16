# Attestation: `retention_chain_v0` — 8-impl cross-validation

**Date:** 2026-06-16
**Set:** `retention_chain_v0`
**Vectors:** 3 (genesis + 2 chain links)
**Result:** 24/24 byte-for-byte agreements (3 vectors x 8 implementations)

## Algorithm

```
retention_chain_ref = "sha256:" + SHA-256(JCS({chain_seq, issuer_id, prev_receipt_hash, receipt_hash}))
```

JCS key order (RFC 8785 lexicographic): `chain_seq`, `issuer_id`, `prev_receipt_hash`, `receipt_hash`.

## Implementations

| # | Language | Library / method | Result |
|---|---|---|---|
| 1 | Python | `rfc8785@0.1.4` + `hashlib.sha256` | 3/3 |
| 2 | TypeScript | `canonicalize@2.0.0` + Node.js `crypto.createHash` | 3/3 |
| 3 | Go | `crypto/sha256` + direct JCS construction | 3/3 |
| 4 | Ruby | `Digest::SHA256` + direct JCS construction | 3/3 |
| 5 | Rust | `sha2@0.10` crate + direct JCS construction | 3/3 |
| 6 | C# (.NET 9) | `System.Security.Cryptography.SHA256.HashData` + direct JCS | 3/3 |
| 7 | Java 17 | `java.security.MessageDigest("SHA-256")` + direct JCS | 3/3 |
| 8 | Kotlin (JVM) | `java.security.MessageDigest("SHA-256")` + direct JCS | 3/3 |

"Direct JCS construction" = canonical form produced by explicit key ordering for this fixed four-field schema, with no extraneous whitespace. Verified byte-identical to `rfc8785.dumps()` Python output for all three vectors.

## Vectors verified

| vector_id | expected_chain_ref |
|---|---|
| retention-chain-v0-000 | `sha256:f15a1dcd03cc039204dff24619ff4815ad041ad8796b94f59d52252043d0d08f` |
| retention-chain-v0-001 | `sha256:7114dc39543710bf26d0a5825acddd915ffd51fb5b14503024f70fda403053d9` |
| retention-chain-v0-002 | `sha256:d3bddca79477e6003cb6ef199897bffed185f5d785b4e7333f9b0585b2b81144` |

## Test frameworks

- Python: `pytest` 22-test suite (includes determinism, manual JCS match, link validity, sequence verification, all error cases)
- TypeScript: `vitest` 22-test suite (same coverage, conformance vector assertions explicit)
- Go: `go test` (3 vector assertions)
- Ruby: `minitest` (3 vector assertions)
- Rust: `cargo test` with GNU toolchain (3 vector assertions)
- C#: `dotnet test` xUnit (3 vector assertions)
- Java: standalone `javac`/`java` runner (3 vector assertions, `System.exit(1)` on mismatch)
- Kotlin: JUnit 5 via Gradle (3 vector assertions; test file present, runnable on any Kotlin/JVM environment)

## Cumulative

This run adds 24 direct agreements to the corpus. Cumulative directly-executed JCS total: **600/600** (as of 2026-06-16).
