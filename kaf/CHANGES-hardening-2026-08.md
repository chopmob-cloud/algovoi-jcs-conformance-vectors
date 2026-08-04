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
