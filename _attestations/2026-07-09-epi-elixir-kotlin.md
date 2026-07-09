# Attestation: Elixir + Kotlin extended to `epi_interop_v0` and `epi_pqc_v0`

**Date:** 2026-07-09
**Sets:** `epi_interop_v0` (5 vectors), `epi_pqc_v0` (4 JCS vectors, signature-suite
anchor out of scope for this claim)
**Result:** 9/9 vector checks PASS across both languages, directly executed,
independently byte-for-byte verified.

## Correction to the earlier same-day assessment

Both sets were initially assumed to need bespoke runners due to their deeply
nested `input` objects (`epi_interop_v0`'s `ManifestModel`-shaped vectors, in
particular). On inspection of each set's `runner_python.py`, both actually reduce
to the exact same shape already handled by `composition/generic_runner_elixir.exs`
/ `composition/GenericRunner.kt`: hash `vector["input"]`, compare against
`vector["frame_id"]` (`sha256:`-prefixed), and check `expected_jcs_bytes_b64`.
JCS canonicalises arbitrarily nested objects the same way regardless of depth, so
no new runner code was needed -- the earlier "different shape, not attempted"
note in `2026-07-09-elixir-kotlin-corpus-extension.md` was overly cautious, not
wrong about the risk, just wrong about needing new code once actually checked.

`epi_pqc_v0` additionally carries a `falcon1024` signature-suite anchor and F7
key-lineage check, which is a separate cryptographic claim (not a JCS
byte-hash claim) and was never part of the 8-language matrix to begin with --
out of scope here, same as `adversarial_isolation_v1`'s Claim 2.

## Commands

```
elixir composition/generic_runner_elixir.exs vectors/epi_interop_v0/epi_interop_v0.json input frame_id 1 expected_jcs_bytes_b64
elixir composition/generic_runner_elixir.exs vectors/epi_pqc_v0/epi_pqc_v0.json input frame_id 1 expected_jcs_bytes_b64
```
Kotlin: same arguments via `java -cp "GenericRunner.jar;<jars>" GenericRunnerKt ...`.

## Results

| Set | Vectors | Elixir | Kotlin |
|---|---|---|---|
| `epi_interop_v0` | 5 | 5/5 | 5/5 |
| `epi_pqc_v0` (JCS only) | 4 | 4/4 | 4/4 |

## Independent byte-for-byte verification

Same rigor as every other set this session: raw computed `sha256:` hashes
extracted independently of each runner's own pass/fail assertion, diffed three
ways per set (expected vs. Elixir, expected vs. Kotlin, Elixir vs. Kotlin).
Zero diff lines across both sets, all three comparisons.

## Updated corpus-wide status

With this addition, **all 11** of the corpus's previously-8-lang anchor sets now
have Elixir and Kotlin directly executed and independently byte-verified:
`retention_chain_v1`, `retention_chain_v0`, `compliance_receipt_v1`,
`settlement_attestation_v1`, `cancellation_receipt_v1`, `refund_receipt_v1`,
`composite_trust_query_v1`, `action_ref_exactly_once_v1`, `pef_v1`,
`epi_interop_v0`, `epi_pqc_v0` (JCS vectors only). `adversarial_isolation_v1`'s
Claim 1 (input bytes) fits the same pattern and could be added the same way in
a future pass; its Claim 2 (rejection behaviour) is a reference-impl proof, not
a byte-hash claim, and stays out of scope regardless of language count.
