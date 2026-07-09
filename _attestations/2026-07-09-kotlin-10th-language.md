# Attestation: Kotlin added as 10th cross-validated language — `retention_chain_v1`

**Date:** 2026-07-09
**Set:** `retention_chain_v1`
**Vectors:** 14
**Result:** 14/14 PASS, directly executed, exit code 0 (run twice)

## Runtime

- JDK 17.0.6 (Oracle, already present on the host)
- Kotlin compiler 2.4.0 — official precompiled release `kotlin-compiler-2.4.0.zip`
  from `github.com/JetBrains/kotlin` releases `v2.4.0`, sha256
  `ba1b9e6eb6ddc3275079224f2e9ea4a2b02eef7d59ce2d38404f04b22613c20a`
  (verified against the release's published `.sha256` before extraction)
- `java-json-canonicalization` 1.1 (Erdtman/Rundgren, the RFC 8785 author's own
  reference implementation) + Jackson 2.17.0 — same JARs already vendored in
  `../runner_java/libs/` for this set's Java runner, reused as-is, not re-fetched

## What was built

`runner_kotlin/` for `retention_chain_v1` is the same `Runner.kt` already written
(unexecuted) for `retention_chain_v0`, copied over and adapted only in a comment —
the vector JSON shape (`vector_id`, `preimage`, `expected_jcs_bytes_b64`,
`expected_chain_ref`) is identical between the two sets, so the logic needed no
changes. Compiled directly to a fat JAR (`-include-runtime`) against the vendored
JARs, no Gradle project needed.

## Commands

```
kotlinc -cp "<jars>" src/main/kotlin/Runner.kt -include-runtime -d runner.jar
java -cp "runner.jar;<jars>" RunnerKt ../retention_chain_v1.json
```

## Result

```
14/14 PASS
```

Exit 0, reproduced on a second run.

## Independent byte-for-byte verification (not just the runner's internal PASS)

Same rigor applied as for Elixir: a separate verbose runner printed the raw
computed `sha256:` hash per vector, bypassing the pass/fail assertion in
`Runner.kt` entirely, then diffed against `retention_chain_v1.json`'s own
`expected_chain_ref` values — and, separately, against the Elixir-computed hashes
from the same session:

```
diff expected_chain_ref vs Kotlin-computed hash   -> IDENTICAL, 0 diff lines (14/14)
diff Elixir-computed    vs Kotlin-computed hash    -> IDENTICAL, 0 diff lines (14/14)
```

This is a genuine three-way cross-implementation agreement (expected / Elixir /
Kotlin), not two runners independently trusting the same pre-computed answer key
without anyone checking the raw bytes.

## What this changes

`retention_chain_v1` now has **10 directly-executed, byte-for-byte-agreeing
implementations**: Python, Node, Go, Ruby, PHP, Rust, Java, .NET, Elixir (this
session, see `2026-07-09-elixir-9th-language.md`), and now Kotlin. This is scoped
to `retention_chain_v1` only — it does not apply to the corpus's other anchor sets,
including `retention_chain_v0` where the Kotlin runner was originally written but
where it (and Elixir) remain unexecuted. The corpus-wide "8 implementations"
headline claim should not move until each anchor set gets its own executed
Elixir + Kotlin runners.
