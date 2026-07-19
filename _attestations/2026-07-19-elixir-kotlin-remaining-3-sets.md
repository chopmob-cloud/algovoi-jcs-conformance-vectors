# Attestation: Elixir + Kotlin extended to the final 3 anchor sets (ten-impl complete)

**Date:** 2026-07-19
**Box:** VM2 clean-box (77.68.52.226), Docker 29.6.2.
**Scope:** the three previously-8-lang directly-executed anchor sets not covered by the
2026-07-09 pass: `action_ref_namespace_v0` (8 vectors), `action_ref_transactional_v0`
(8 vectors), `settlement_action_binding_v1` (6 vectors).

**Result:** 22 vectors x 2 languages = **44/44 byte-for-byte agreements PASS**. With this
run, all 14 directly-executed anchor sets are validated across ten independent JCS
implementations in ten programming languages.

## Toolchains (fresh Docker containers, no local state)

- Elixir: `elixir:latest` -> Elixir 1.20.2 (compiled with Erlang/OTP 29); JCS via
  `jcs` 0.2.0 (pzingg/jcs, hex.pm), resolved by `Mix.install`. Byte-for-byte parity
  additionally confirmed on `elixir:1.18` -> Elixir 1.18.4 / OTP 28 (JCS is
  deterministic across minor versions).
- Kotlin/JVM: the 2026-07-09-compiled `GenericRunner.jar` (Kotlin 2.4.0,
  `java-json-canonicalization` 1.1) run on `eclipse-temurin:17-jdk` (OpenJDK 17.0.19).

## Method

Each set was run through the corpus's generic JCS hash-comparison runners
(`composition/generic_runner_elixir.exs`, `composition/GenericRunner.jar`), which for
every vector recompute `base64(JCS(preimage))` and `sha256(JCS(preimage))` and compare
byte-for-byte against the set's `expected_jcs_bytes_b64` and expected-hash field
(`expected_action_ref` / `expected_transition_hash` / `expected_content_sha256`). Both
languages reproduced the existing eight-language reference hashes exactly, so each
independently agrees with the reference and therefore with each other.

| Set | Vectors | Elixir (jcs 0.2.0) | Kotlin (java-json-canonicalization 1.1) |
|---|---|---|---|
| action_ref_namespace_v0 | 8 | 8/8 PASS | 8/8 PASS |
| action_ref_transactional_v0 | 8 | 8/8 PASS | 8/8 PASS |
| settlement_action_binding_v1 | 6 | 6/6 PASS | 6/6 PASS |

## Combined directly-executed cumulative

880 (eight-language base, through 2026-06-18) + 172 (Elixir + Kotlin x 11 sets,
2026-07-09) + 44 (this run) = **1096/1096** byte-for-byte agreements directly executed
across ten independent implementations.
