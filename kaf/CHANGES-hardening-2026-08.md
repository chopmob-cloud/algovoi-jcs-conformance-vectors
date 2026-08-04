# KAF substrate hardening, change log and backward-compatibility verdict (2026-08)

This document records every change made during the KAF (Keystone Assurance
Framework) security and validation campaign, and the verification that proves
those changes are backward compatible with the published AlgoVoi packages and
compatible with the key apps that consume the substrate.

Scope of the campaign: harden the JCS conformance substrate, the P1 to P6
harnesses, the receipt-minting and offline-verify path, and the language
canaries, without changing any vector payload or any canonical byte that a
published package reproduces.

Governing constraint: all work is local. Nothing in this campaign was pushed or
published. The GitHub publication gate remains intact.

## 1. What changed, by repository

### 1a. Corpus (`algovoi-jcs-conformance-vectors`), 29 files

No vector payload (`.json` under `vectors/` or `composition/`) was changed. Every
change is either stricter runner logic, a harness hardening, an additive seal
receipt, or a one-line manifest note. Because the bytes are untouched, no
published package sees a different input.

Runners (added stricter binding checks, positive-work floors):

| file | change |
|---|---|
| `vectors/jcs_parse_v1/runner_python.py` | verify `input_sha256` in both the accept and reject loops, and check `expected_code` on rejects |
| `vectors/jcs_edge_v1/runner_python.py` | validate the declared `expected_content_hash` |
| `vectors/retention_chain_v0/runner_python.py` | verify `receipt_hash == "sha256:"+sha256(receipt_preimage)` and the `preimage.receipt_hash` binding, plus an empty-input floor |
| `vectors/retention_chain_v1/runner_python.py` | same receipt-binding verification |
| `vectors/multichain_ed25519_substrate_v0/verify.py` | verify `payload_sha256`, add an empty-signatures floor, import `hashlib` |
| `vectors/revocation_ref_v1/runner_python.py` | positive-work floor (empty input must not pass) |
| `vectors/trust_gate_v1/runner_python.py` | positive-work floor |
| `composition/keystone_gauntlet/tg_python.py` | positive-work floor |
| `composition/keystone_gauntlet/rev_python.py` | positive-work floor |

Composition probe and differential driver:

| file | change |
|---|---|
| `composition/differential_adversarial/differential_driver.py` | strict N-way verdict membership: a consensus round requires every verdict to be uniformly `h:` (hash) or `R:` (reject), never a mixed set |
| `composition/differential_adversarial/probe_php.php` | add `JSON_UNESCAPED_LINE_TERMINATORS` so the PHP probe emits raw U+2028/U+2029, matching the RFC 8785 byte expectation |

KAF harnesses (seal and offline verify):

| file | change |
|---|---|
| `kaf/seal.py` | F6/F7/F-A/F-B/F-C/F-E. `_canon` cross-checks its output against an independent in-process canonicalizer (`_jcs_min`). F-A belt refuses to seal a run that declares a consensus without a bound consensus record. `--evidence-kind` CLI flag makes attestation-only intent explicit. `_is_zero` bool guard (a boolean False is not a zero rc). Honest `canon_cross_checks` metadata (records that the only genuinely independent in-process check is `_jcs_min`; real cross-impl independence is the 10-language consensus). |
| `kaf/kaf_verify.py` | F7 delimiter-bounded `created` match (`(?:^|;)created={...}(?=;|$)`) so a prefix cannot satisfy the check; `_is_zero` in the greenness re-derivation |

Language canaries (fail-closed on ambiguity):

| file | change |
|---|---|
| `kaf/net_canary.py` `.mjs` `.php` `.rb` | F-1: a connection timeout is inconclusive (for example a firewall drop), not proof of isolation, so it is treated as reachable and fails closed. Only a genuine no-route error (ECONNREFUSED/ENETUNREACH/EHOSTUNREACH) counts as the isolated hermetic state. |

Seal chain (additive, no existing receipt changed):

| file | change |
|---|---|
| `kaf/receipts/rcpt-000004..000013` | receipts seq 4 to 13 for the hermetic P1 to P5 re-runs, the 10-way consensus, the comprehensive byte-for-byte prover, and the exhaustive strata blast, all under the hardened code |
| `kaf/receipts/CHAIN_HEAD.txt` | count=13, head pinned to `2c3b53831c2dd694a15e44da57147f6616a8629cc30b0ede2ae08be86cd730dd` |

Manifest:

| file | change |
|---|---|
| `manifest.json` | one-line `total_vectors_note` correction (43 sets / 352 entries, "independently recomputed 2026-08-03"). `total_anchor_sets` and `total_vectors` were already 43 and 352. |

### 1b. RFC 9421 verifier (`algovoi-rfc9421-verifier`), 3 source files

These are the only changes to a shipped app's source. All three are fail-closed:
they reject a malformed or malicious input and cannot reject a legitimate,
canonically-encoded signature.

| file | change | backward-compat safety |
|---|---|---|
| `python/.../content_digest.py` | D-F1: fail if no entry used a recognized algorithm (a header of only unknown algos verified nothing and must not return True). Also reject non-canonical base64 in a digest entry. | Legitimate Content-Digest headers use sha-256/sha-512 (recognized) and canonical base64, so they are unaffected. Only the vacuous or malformed case is newly rejected. |
| `python/.../verify.py` | D-F2: when content-digest verification is required, the `content-digest` component must be a covered signature component, not merely present, else a body swap with a recomputed digest still verifies. | Gated behind the require-content-digest path. A correct signer that requires body integrity already covers content-digest. |
| `python/.../parse.py` | D-F7: reject a non-canonical base64 signature value (non-zero pad bits), which otherwise lets roughly 16 header encodings decode to the same Ed25519 signature and all verify, breaking any replay or dedup key derived from the raw header. | Legitimate Ed25519 signatures round-trip canonically. |

### 1c. Platform (`platform`), net-new P1 to P6 tooling

The `tools/kaf-p1..p5`, `tools/kaf-evidence`, and `tools/appcheck` trees are
net-new (2254 insertions, 0 deletions; they did not exist on `origin/master`).
They add behavior, they do not change any existing behavior. The hardening within
them (positive-work floors in `bff_all.py`/`bff_pkg.py`/`bff_node.mjs`,
`manifest_bff.py` no-anchor gate, `strata_blast.py` exit gate and whole-tree
copy, `orchestrate_p2.py` F-N1/F-N3, `orchestrate_p3.py` F-A/F-5,
`wrap_report_run.py` fail-closed) landed before first publication, so there is no
prior behavior to break.

## 2. Backward-compatibility verdict

The published-artifact compatibility verdict of 2026-08-03 (see
`platform/tools/appcheck/README.md`, memory claim 9848) established zero
substrate incompatibilities across 23 public-PyPI and 5 npm published packages.

This campaign preserves that verdict, proven two ways:

1. Byte invariant. Zero vector payloads changed (confirmed by
   `git diff --name-only origin/main..HEAD -- 'vectors/**/*.json'
   'composition/**/*.json'`, filtered of runners, returns nothing). Every input a
   published package reproduces is byte-identical to what it reproduced before.

2. Stricter-runner invariant. The new runner checks (input_sha256,
   receipt-binding, expected_content_hash, positive-work floors) do not newly-fail
   any previously-green vector. A full sweep of all 49 corpus runners against their
   data under the hardened checks returns 49 green, 0 red, 0 skipped.

Together these close the only two ways this campaign could have broken backward
compatibility (change the bytes, or make a runner stricter in a way that rejects a
valid vector). Neither occurred.

## 3. P1 to P6 compatibility with the key apps

| app | check | result |
|---|---|---|
| `algovoi-rfc9421-verifier` | own pytest suite (source hardened) | 23 passed |
| `algovoi-rfc9421-verifier` | corpus `rfc9421_proxy_chain_v0/v1`, `rfc9421_receipt_evidence_v0` | green in the 49-set sweep |
| `algovoi-key-credential-binding` (kcb) | own pytest suite | 12 passed |
| `algovoi-substrate` | own pytest suite (base every runner reproduces) | 272 passed |
| `avm-proofpack` | full pytest suite | 538 passed, 3 skipped |
| `avm-proofpack` | substrate-binding subset (vectors, settlement-evidence-binding, chains, stateproof) | 62 passed |
| Keystone chain (P6) | offline `kaf_verify.py`, 13 receipts, head pinned | 13/13 VERIFIED |
| corpus P1 to P5 substrate | all 49 runners against their vectors | 49/49 green |

Note on `avm-proofpack`: the full suite initially raised a `PermissionError`
resolving pytest's `pytest-current` symlink under the Windows temp dir. This is an
environment artifact, not a substrate incompatibility; rerunning with an explicit
`--basetemp` under the scratchpad passes 538/3.

## 4. How to reproduce this verification

From `algovoi-jcs-conformance-vectors`:

```
# 1. byte invariant: zero vector payloads changed since the appcheck verdict
git diff --name-only origin/main..HEAD -- 'vectors/**/*.json' 'composition/**/*.json'

# 2. stricter-runner invariant: every corpus runner green under the hardened checks
for d in vectors/*/; do
  s=$(basename "$d")
  [ -f "$d/runner_python.py" ] && [ -f "$d/$s.json" ] && \
    ( cd "$d" && python runner_python.py "$s.json" >/dev/null && echo "ok  $s" || echo "RED $s" )
done

# 3. offline P6 chain verify
python kaf/kaf_verify.py --receipts-dir kaf/receipts \
  --pub-file kaf/keys/kaf-seal.pub.json --genesis-anchor kaf/MANIFEST.txt \
  --expect-count 13 \
  --expect-head 2c3b53831c2dd694a15e44da57147f6616a8629cc30b0ede2ae08be86cd730dd
```

Key-app suites: `python -m pytest -q` in `algovoi-rfc9421-verifier/python`,
`platform/algovoi-key-credential-binding`, `algovoi-substrate`, and
`avm-proofpack` (the last with `--basetemp` set to a writable dir).

## 5. Classification of every finding fixed

Every defect fixed in this campaign is in one of three classes: fail-closed
(ambiguous state treated as failure), honesty (metadata or labeling that could
overstate what was proven), or coverage (a check that was declared but not
enforced, or a zero-work run that could seal green). None was a forge or an
authenticity break: the crypto core rejected all 17 tamper attacks and every
receipt verifies. No fix changed a canonical byte.

## 6. Addendum, 2026-08-04: full flagged trust-model batch

The items flagged for review at the end of the overnight sweep were implemented as
a batch, tested locally, and validated on the clean-docker dev server.

- **F-N2, corpus-commit binding through the report-attestation wrap.**
  strata_blast.py and p5_chains.py embed corpus_commit; wrap_report_run.py refuses
  a report whose commit is absent or != the asserted --corpus-commit. Tested both
  ways.
- **F-N4, 10-language in-cell hermeticity attestation.** Added in-cell network
  canaries for the six compiled/other N-way languages (go, rust, java, kotlin,
  dotnet, elixir) mirroring net_canary.py, plus positive attestation: a passing
  canary now writes canary\t0, so its presence can be required. Wired into
  p3_provision.sh (build) and p3_exec.sh (run). Validated in real cells on the dev
  server: all 10 languages report NETWORK=NONE and emit canary\t0.
- **kaf receipt schema v3 (catalog anchor + canary requirement).** seal.py
  --catalog binds the coverage catalog into the signed body; cells[] must be a
  superset of it (coverage cannot be trimmed), and every cell-execution cell must
  carry a passing canary suite. kaf_verify.py is schema-aware: v2 unchanged, v3
  re-derives the catalog-superset and canary properties. The orchestrators emit
  catalog.json (the full mandated cell set). Tested both ways with a throwaway
  keypair; a validly-signed receipt with trimmed coverage is still rejected.
- **Verify-time N-way consensus re-derivation.** Under --evidence-dir, kaf_verify
  re-runs the differential driver over the harvested per-language verdict files
  and requires full consensus (defense-in-depth atop the existing tree-binding).
- **KAF_RESUME staleness.** Result dirs are stamped with the run_id; aggregation
  degrades a dir left over from a different run, so a stale artifact cannot satisfy
  the seal.
- **G-1 manifest reconcile.** Registered two previously-unlisted on-disk JCS sets
  (atb_trust_v1 6, revocation_ref_v1 16): total_anchor_sets 43 -> 45, total_vectors
  352 -> 374. trust_gate_v1 (15) is a non-JCS verdict table, registered in a new
  gate_sets category and NOT folded into the anchor totals. manifest_bff verifies
  gate_sets too. External citations of 352 should be synced to 374.
- **F-C1, already covered.** jcs_edge_v1 already carries U+2028/U+2029 (edge-001/002)
  and the & < > HTML literals (edge-009); no new vectors were needed.

F-6 dependency pinning: done. rfc8785 is pinned to ==0.1.4 in p3_provision.sh, and
the exact host-side dependency set (validated on the dev server) is recorded in
kaf/requirements-pinned.txt (algovoi-substrate 0.5.1, rfc8785 0.1.4, PyNaCl 1.6.2,
cryptography 50.0.0, pqcrypto 0.4.0, algovoi-execution-ref 0.1.0).

substrate_guard_v1 count: not an error. Its top-level arrays sum to 14 but the
runner tests 15/15 and the manifest's vector_count=15 matches the runner (the
authoritative operational count), so 374 stands.

P4 and P5 were also re-run fresh on the dev server under the hardened code: P4
strata 634/634 forgeries rejected (0 escapes, 0 baseline failures), P5 10/10
chains + 5/5 gauntlets, and both reports embed corpus_commit=ccf8b78, confirming
the F-N2 wrap binding end to end. They run host-side (in-process fuzzers), so they
are not sealed with a docker image label; the two v3 chain receipts (seq14 P3,
seq15 P2) come from genuine hermetic docker cells with accurate image digests.

### Dev-server validation (fresh, hardened code)

The P3 full 10-way differential rejection consensus was re-run hermetically on the
clean-docker dev server under the hardened code: 10/10 languages, consensus_rc=0,
all six new compiled-lang canaries validated in real cells. It was harvested and
sealed locally with the real kaf-seal-2026 identity as the chain's first v3
receipt (seq14 P3 + seq15 P2, catalog-anchored). The full chain now verifies 15/15 offline
(v2 seq1-13 + v3 seq14-15), and seq4-15 re-derive under --evidence-dir including the
seq14 consensus re-derivation. All local batteries stay green (tamper 17/17,
fa_matrix, degen 5/5, bff_all, manifest_bff 45/374 + gate_sets, 49-runner sweep).
