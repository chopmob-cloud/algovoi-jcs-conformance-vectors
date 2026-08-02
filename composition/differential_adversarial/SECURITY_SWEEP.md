# Security sweep — differential adversarial substrate

Date: 2026-08-02. Reviewer discipline: offensive/audit (threat-model first).
Full run: local (Windows) 9/10 + VM2 (Linux) 10/10 twice, plus the whole
existing hardening suite on VM2 (see bottom).

## Threat model

This framework's product is *confidence* that ten independent JCS
implementations agree, and a map of where they diverge. The adversary is
therefore a **false-green**: any path where the tool reports "FULL 10-WAY
CONSENSUS" without having proven it, or a coverage gap that hides a real
divergence. Inputs (the corpora) are trusted and authored by us; each `raw`
string is deliberately hostile and is re-parsed by each probe. Every failure
mode below is either closed *and proven to fail closed*, or documented as an
explicit out-of-scope limitation.

## Failure modes and disposition

| # | Way it could fail (false-green or gap) | Disposition | Proven? |
|---|---|---|---|
| 1 | Missing toolchain shrinks N; consensus over fewer impls still "passes" | `--require N` gate; NOT GREEN if `present < N` | VM2 negative test: require 11 → NOT GREEN |
| 2 | A probe crashes/emits partial output; absent case treated as pass | Coverage gate: every present impl must emit every case id | VM2 negative test: drop 1 verdict → NOT GREEN |
| 3 | All ten wrong the same way (shared systematic error) | 17 independent KAT anchors (`expected_hash` from `printf\|sha256sum`, no JCS lib); + 10 distinct libraries; + relational `differs_from` canary | VM2 negative test: corrupt 1 KAT → NOT GREEN |
| 4 | Empty/degenerate corpus passes vacuously | Gate: `n_pass+n_fail>0` and `n_kat>0` required | Gate present; trips on empty input |
| 5 | Probe forges a verdict line by echoing `raw`/exception text | All 10 probes emit only `<trusted id>\t<fixed token>` (`h:hex` or `R:reason`); never echo `raw` or exception messages | Source-reviewed all 10 probes |
| 6 | A "reject" case that some impls accept → spurious pass or false split | Only truly-universal invalid-JSON in the reject set; empirically-divergent tokens (leading-zero, `+1`, `0x10`, comments, `.5`, `1.`) moved to the hazard map, never forced to "reject" | Reclassified after observed splits (e.g. leading-zero) |
| 7 | Flaky/non-deterministic green | Probes use no time/rng; byte-identical hashes across 2 VM2 passes + local | Two VM2 passes identical |
| 8 | Relational invariant references an absent case | `agreed_hash.get()` → None; `same_as`/`differs_from` fail closed | Code path fails closed |
| 9 | Malformed corpus JSON silently skipped | Driver/probes hard-error on bad JSON (fail-loud) | Hit during sweep: a missing comma → hard crash, not silent pass |
| 10 | Cross-platform byte divergence (CRLF/encoding) | Probes read/emit UTF-8; LF-normalized; validated Windows + Linux | Local + VM2 identical |

## Coverage (attack classes exercised, 58 cases)

- **Numbers:** 0, negative, safe int, >2^53, 30-digit, float, 0.1, -0, exponent,
  uppercase `E`, `e+`, overflow (`1e400`), NaN, Infinity, leading zero, leading
  `+`, hex, leading/trailing dot, `1.0`.
- **Strings:** quote/backslash escapes, non-escaped `/`, tab/control, NFC
  precomposed, `\u` escape decode, supplementary-plane value (emoji), lone
  surrogate, decomposed Unicode.
- **Structure:** key ordering, nested sort, array-order preservation, empty
  containers, insignificant whitespace, duplicate keys, top-level empty
  object/array, unterminated object/array, trailing garbage, two top-level
  values, **supplementary-plane key sort (UTF-16 §3.2.3)**.
- **Tier-semantic:** real L2/L3 preimages (decision_audit, guard_context,
  revocation_link, settlement) with key-order (`same_as`) and tamper
  (`differs_from`) invariants across all ten.

Three hardest Unicode cases were resolved against independent oracles and proven
**RFC-8785-correct across all ten** (not shared bugs): supplementary value = raw
UTF-8; `é` → raw é; supplementary keys sort by UTF-16 code unit.

## Explicit out-of-scope / limitations (honest)

- **In-process deep-nesting is not fuzzed.** A stack overflow in a parser is
  uncatchable in some runtimes (e.g. .NET) and would abort the whole probe,
  which the coverage gate would (correctly) read as failure — but it is a
  denial-of-availability concern, not a canonicalization-divergence one, and
  belongs in an isolated one-input-per-process harness. Documented, not run here.
- **Signature layer (Ed25519) is out of scope for this framework.** It is covered
  by `execution_ref`/settlement vectors and by the Concordia interop check (our
  JCS reproduces their hash and our verifier validates their signature).
- **17 of 38 agree cases carry KAT anchors.** The remainder are consensus-only;
  the tricky-escape cases were left un-pinned because a hand-derived anchor is
  error-prone under the corpus double-parse (a mismatch was caught and excluded
  rather than pinned wrong).
- **Local is 9/10** (no elixir toolchain on the Windows box); **VM2 is the 10/10
  authority**, run twice.

## Whole-suite context (VM2, same session)

L1 verify_corpus 47/0 · first_principles 11/11 · mutation_fuzz 40 tested / 0
escapes · adversarial 96/96. L2/L3 gauntlets: keystone 80/80, guard_context
70/70, settlement_round 50/50, trust_gate 150/150, revocation 160/160 (510/510).
Differential: 10-way, 38/38 + 7/7 + 17 KAT + integrity gates, twice.
