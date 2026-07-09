# Attestation: Elixir added as 9th cross-validated language — `retention_chain_v1`

**Date:** 2026-07-09
**Set:** `retention_chain_v1`
**Vectors:** 14
**Result:** 14/14 PASS, directly executed, exit code 0 (run twice, cold and warm dep cache)

## Runtime

- Erlang/OTP 29 (erts-17.0.3), installed via `winget install Erlang.ErlangOTP` (official Ericsson AB package, 29.0.3)
- Elixir 1.20.2, compiled for Erlang/OTP 29 — official precompiled release
  `elixir-otp-29.zip` from `github.com/elixir-lang/elixir` releases `v1.20.2`,
  sha256 `a9e88cd41fbbba7da6f6dc237a49dd2ed4e70457121035cc7fc56ad05582f394`
  (verified against the release's published `.sha256sum` before extraction)
- `jcs` 0.2.0 ([pzingg/jcs](https://github.com/pzingg/jcs) on hex.pm) — independent
  third-party pure-Elixir RFC 8785 implementation, not AlgoVoi-authored
- `jason` 1.4.5 (hex.pm) — JSON decode only, not part of the canonicalisation claim

Both deps fetched via `Mix.install/1` inline in `runner_elixir.exs` — no scaffolded
mix project, consistent with the corpus's single-file-runner convention.

## Command

```
elixir runner_elixir.exs retention_chain_v1.json
```

## Result

```
14/14 PASS
```

Exit 0. Re-run after dependency cache was warm: identical result, exit 0.

## What this changes

`retention_chain_v1`'s README previously documented 8 directly-executed languages
(Python, Node, Go, Ruby, PHP, Rust, Java, .NET). This run is the first live execution
of the Elixir runner drafted the same day — it is now a 9th directly-executed,
byte-for-byte-agreeing implementation for this anchor set specifically. This does
NOT retroactively apply to the other 33 anchor sets in the corpus, which remain at
their previously-attested language counts until each is run individually. The
corpus-wide "8 implementations" headline claim in `conformance-vectors.mdx` and the
top-level `README.md` should not be bumped to 9 until Elixir runners exist and are
executed for the other 8-lang sets too (`compliance_receipt_v1`,
`settlement_attestation_v1`, `cancellation_receipt_v1`, `refund_receipt_v1`,
`composite_trust_query_v1`, `pef_v1`, `epi_interop_v0`, `epi_pqc_v0`,
`retention_chain_v0`, `action_ref_exactly_once_v1`, `adversarial_isolation_v1`).

## Also discovered this session

`retention_chain_v0/runner_kotlin/` already exists (written earlier, never executed —
no Kotlin CLI available at the time it was written). Not addressed in this run; a
separate pass would be needed to install a Kotlin/JVM toolchain and execute it before
any Kotlin claim can be made.
