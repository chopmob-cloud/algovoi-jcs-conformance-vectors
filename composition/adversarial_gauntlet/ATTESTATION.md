# Adversarial gauntlet — 8-implementation fail-closed attestation

**Run date:** 2026-06-19
**Vector set:** `adversarial_isolation_v1` (1 control + 11 isolated rejections)
**Result:** **96/96 fail-closed verdicts** — 8 implementations × 12 vectors, all green.

## What this attests (and what it does not)

The published corpus already attests **Claim 1 (input bytes)**: every adversarial
input canonicalises byte-for-byte across 8 RFC 8785 implementations. The corpus
limited **Claim 2 (rejection)** to the reference implementation only — *"NOT an
8-lang byte claim"* — because business-logic rejection is a property of the
validator, not of JCS.

This gauntlet closes that gap: it attests **Claim 2 across 8 implementations**.
Each runner is an **independent reimplementation** of the three substrate-1 checks
(`transition_preimage`, `action_ref`, `audit_chain`) — no `algovoi` package import —
and every one **accepts the control and rejects all 11 mutations identically**.

Positive cross-validation (832/832) proves 8 impls *agree on valid inputs*. This
proves the harder property: 8 independent impls all *fail closed on every attack*,
the same way. A single-implementation fork cannot demonstrate it.

## Measured result

| Implementation | Toolchain (this run) | Verdicts |
|---|---|---|
| Python  | 3.12.10        | 12/12 |
| Node    | v24.12.0       | 12/12 |
| Ruby    | 3.4.9          | 12/12 |
| PHP     | 8.4.20         | 12/12 |
| Go      | go (gc)        | 12/12 |
| Rust    | 1.95.0 (stable-gnu) | 12/12 |
| Java    | 17.0.6 (Jackson 2.17) | 12/12 |
| .NET    | 9.0.314 (System.Text.Json) | 12/12 |
| **Total** | | **96/96** |

The 12 vectors exercise: RFC-3339-string timestamp, negative timestamp, boolean
timestamp, non-hex `action_ref`, short `action_ref`, empty `state`, identity
RFC-3339 timestamp, empty `scope`, broken chain link, stale `content_hash`, and
wrong `chain_position` — plus the valid control (which every impl must accept).

## Reproduce

```bash
bash composition/adversarial_gauntlet/run_gauntlet.sh
```

Runs all eight runners against `vectors/adversarial_isolation_v1/` and prints the
per-impl and total verdict count. Exit 0 only when all 96 are green.

## Scope notes (no overclaim)

- Each runner reimplements the **validation rules**, not the substrate; the point
  is that the rules are language-portable and fail-closed in every language.
- The `audit_chain` content-hash recompute uses canonical **sorted-key compact
  JSON**, which is byte-identical to RFC 8785 JCS for the ASCII-string / integer
  payloads in this vector set (verified: `{"event":"issue","n":1}` →
  `a20a9727…`, `{"event":"settle","n":2}` → `73cfebca…`).
- **Rust** builds with the `stable-x86_64-pc-windows-gnu` toolchain (the default
  MSVC toolchain hit a `serde_core` build-script error on this host); the harness
  pins the gnu toolchain, matching the existing 8-impl runner.
