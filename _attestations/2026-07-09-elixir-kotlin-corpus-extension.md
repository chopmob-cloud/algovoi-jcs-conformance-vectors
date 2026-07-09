# Attestation: Elixir + Kotlin extended to 9 anchor sets (10-impl now)

**Date:** 2026-07-09
**Scope:** `compliance_receipt_v1`, `settlement_attestation_v1`, `cancellation_receipt_v1`,
`refund_receipt_v1`, `composite_trust_query_v1`, `retention_chain_v0`,
`action_ref_exactly_once_v1`, `pef_v1` — plus `retention_chain_v1` from the same day's
earlier attestations (`2026-07-09-elixir-9th-language.md`,
`2026-07-09-kotlin-10th-language.md`).

**Result:** 63/63 vector checks PASS across both languages (8 sets × runner, plus
`pef_v1`'s two-pass receipt+frame_id check), directly executed, byte-for-byte
independently verified.

## What was built

A single generic, parameterised runner per language instead of one bespoke runner
per set, since these 8 sets share the same shape (hash a named JSON field, compare
against a named expected-hash field, optionally with a `sha256:` prefix) — they just
use different field names per set (and, within `compliance_receipt_v1` /
`settlement_attestation_v1` / `cancellation_receipt_v1` / `refund_receipt_v1` /
`composite_trust_query_v1`, two different field-name pairs for receipt vectors vs.
audit-chain-row vectors):

- `composition/generic_runner_elixir.exs` — `jcs` 0.2.0 (pzingg/jcs, hex.pm)
- `composition/GenericRunner.kt` — `java-json-canonicalization` 1.1, reusing the
  same vendored JARs as the existing Java runners

Both take `<json> <payload_fields> <hash_fields> <prefix:0|1> [b64_fields]`, where
`payload_fields`/`hash_fields` accept a comma-separated fallback list — the first
key actually present on each vector is used. This mirrors the corpus's own reference
runners' logic exactly (e.g. `compliance_receipt_v1/runner_python.py`'s
`v.get("receipt") or v.get("row")`).

## A real bug caught by verification, not assumed away

The first pass produced genuine failures: `compliance_receipt_v1` and its four
siblings failed 3 of 8 vectors each, and `action_ref_exactly_once_v1` failed 5 of 6.
Root cause in both cases was the same class of mistake — a single static field name
where the set actually uses different field names for different vector kinds
(receipt vs. audit-chain row; `expected_action_ref` vs. `expected_transition_hash`
depending on `pair_group`). This was a bug in the generic harness, not in JCS, in
Elixir, or in Kotlin — confirmed by reading each set's `runner_python.py` reference
logic before fixing the harness to try both field names in order. Re-run after the
fix: 0 failures across all 8 sets, both languages.

## Independent byte-for-byte verification (not just each runner's internal PASS)

For every one of the 8 sets, a separate raw-hash dump (bypassing each runner's own
pass/fail assertion) was diffed three ways per set:

```
expected_content_hash (from the vector JSON) vs. Elixir-computed  -> IDENTICAL
expected_content_hash (from the vector JSON) vs. Kotlin-computed  -> IDENTICAL
Elixir-computed                              vs. Kotlin-computed  -> IDENTICAL
```

Zero diff lines across all 8 sets, both comparisons. (The first raw `diff` run
showed spurious line-level differences that were CRLF-vs-LF only, from Kotlin's
`println` on Windows — confirmed identical content with a whitespace-insensitive
diff before concluding PASS.)

## Per-set commands used

```
elixir composition/generic_runner_elixir.exs vectors/compliance_receipt_v1/compliance_receipt_v1.json receipt,row expected_content_hash,expected_row_content_hash 0 expected_jcs_bytes_b64
elixir composition/generic_runner_elixir.exs vectors/settlement_attestation_v1/settlement_attestation_v1.json receipt,row expected_content_hash,expected_row_content_hash 0 expected_jcs_bytes_b64
elixir composition/generic_runner_elixir.exs vectors/cancellation_receipt_v1/cancellation_receipt_v1.json receipt,row expected_content_hash,expected_row_content_hash 0 expected_jcs_bytes_b64
elixir composition/generic_runner_elixir.exs vectors/refund_receipt_v1/refund_receipt_v1.json receipt,row expected_content_hash,expected_row_content_hash 0 expected_jcs_bytes_b64
elixir composition/generic_runner_elixir.exs vectors/composite_trust_query_v1/composite_trust_query_v1.json response,row expected_content_hash,expected_row_content_hash 0 expected_jcs_bytes_b64
elixir composition/generic_runner_elixir.exs vectors/retention_chain_v0/retention_chain_v0.json preimage expected_chain_ref 1 expected_jcs_bytes_b64
elixir composition/generic_runner_elixir.exs vectors/action_ref_exactly_once_v1/action_ref_exactly_once_v1.json preimage expected_action_ref,expected_transition_hash 0 expected_jcs_bytes_b64
elixir composition/generic_runner_elixir.exs vectors/pef_v1/pef_v1.json receipt expected_receipt_hash 1 expected_receipt_jcs_bytes_b64
elixir composition/generic_runner_elixir.exs vectors/pef_v1/pef_v1.json preimage expected_frame_id 1 expected_preimage_jcs_bytes_b64
```

Kotlin: same arguments via `java -cp "GenericRunner.jar;<jars>" GenericRunnerKt ...`.

## Results per set

| Set | Vectors | Elixir | Kotlin |
|---|---|---|---|
| `compliance_receipt_v1` | 8 | 8/8 | 8/8 |
| `settlement_attestation_v1` | 8 | 8/8 | 8/8 |
| `cancellation_receipt_v1` | 8 | 8/8 | 8/8 |
| `refund_receipt_v1` | 8 | 8/8 | 8/8 |
| `composite_trust_query_v1` | 8 | 8/8 | 8/8 |
| `retention_chain_v0` | 3 | 3/3 | 3/3 |
| `action_ref_exactly_once_v1` | 6 | 6/6 | 6/6 |
| `pef_v1` (receipt pass) | 8 | 8/8 | 8/8 |
| `pef_v1` (frame_id pass) | 8 | 8/8 | 8/8 |

## What this does NOT cover

`epi_interop_v0` and `epi_pqc_v0` use a materially different, deeply-nested
ManifestModel/PEF-composite structure (not addressed by the generic runner) —
extending Elixir/Kotlin coverage there would need bespoke runners, not attempted
in this pass. `adversarial_isolation_v1`'s Claim 1 (input bytes) fits this pattern
and could be added the same way; Claim 2 (rejection behaviour) is a reference-impl
proof-of-rejection, not a byte-hash claim, and was never an 8-lang claim to begin
with, so it is out of scope regardless.

`retention_chain_v1` is not re-listed above since it was already covered and
attested in `2026-07-09-elixir-9th-language.md` /
`2026-07-09-kotlin-10th-language.md` earlier the same day.

## Corpus-wide claim

With this run, **9 of the corpus's 11 previously-8-lang anchor sets** now have a
directly-executed, byte-for-byte-verified 10th and 9th (Elixir, Kotlin)
implementation: `retention_chain_v1`, `compliance_receipt_v1`,
`settlement_attestation_v1`, `cancellation_receipt_v1`, `refund_receipt_v1`,
`composite_trust_query_v1`, `retention_chain_v0`, `action_ref_exactly_once_v1`,
`pef_v1`. The remaining two (`epi_interop_v0`, `epi_pqc_v0`) stay at 8 until
addressed separately. The top-level `README.md` headline is updated to reflect
this split rather than rounding up to a blanket "10 implementations" claim.
