# KAF: Keystone Assurance Framework (in-repo harness)

An AlgoVoi original. This directory implements phases P1 (hermetic runtime
cells) and P2 (the Keystone Seal) of `kaf/DESIGN.md`, the design of record.

## What this is

The corpus stops being "a list of vectors" and becomes a measured system on
four axes: **agreement** (independent implementations in byte-exact
consensus), **strata** (generated coverage of the input space), **cells**
(runtime environments the verdicts hold in), and **seal** (signed,
hash-chained, offline-verifiable evidence).

## P1: hermetic runtime cells

A cell is (language, runtime version, libc variant), pinned in
`cells.json` and resolved to an exact image digest per run
(`cells.lock.json`). The contract:

- **Provisioning** runs with network ON as a recorded exception
  (`provision_cell.sh`): interpreter dependencies land on a volume, the
  outcome (pip freeze, any per-package failure) is written to
  `provision.json` and embedded in the receipt.
- **Execution** runs with `--network=none` (`cell_exec.sh` via
  `run_cell.sh`): the corpus is mounted read-only, a network canary (a real
  program file) must prove the network unreachable, and every suite runs as
  a real module. The **real-module rule** is absolute: nothing executes via
  `-e`/`-c`/REPL contexts, which inject globals that mask environment
  defects (the Node 18 `crypto.subtle` lesson).
- Suites per cell: the L1 composition checks (`verify_corpus`,
  `first_principles`, `adversarial_jcs`, `mutation_fuzz`) on python cells,
  and the single-language per-set matrix (`run_matrix_lang.sh`) everywhere.

Run on the host (VM2):

    bash kaf/orchestrate_p1.sh <run_id> [cell_id ...]

## P2: the Keystone Seal

`seal.py` turns a green run into a sealed receipt:

1. The receipt body is JCS-canonicalized with **algovoi-substrate** and
   must byte-match the independent **rfc8785** implementation (a
   differential check inside the sealer).
2. The seal is an **RFC 9421 + RFC 9530** signature over a synthetic HTTP
   message carrying those bytes, produced by the **published**
   `algovoi-rfc9421-signer`.
3. The envelope file IS its canonical bytes; its sha256 is the chain link.
   Each receipt names its predecessor's digest; the first is anchored to
   the P0 snapshot MANIFEST, committed here as `kaf/MANIFEST.txt` (sha256
   `e5282959...`). History cannot be reordered or backdated.

`kaf_verify.py` re-proves all of it **offline** with the **published**
`algovoi-rfc9421-verifier` against the pinned key in
`keys/kaf-seal.pub.json`:

    python kaf/kaf_verify.py --receipts-dir kaf/receipts \
        --pub-file kaf/keys/kaf-seal.pub.json \
        --genesis-anchor kaf/MANIFEST.txt --expect-count 3

The framework certifies itself with the primitives it certifies. That is
the stamp.

## Keys

`keys/kaf-seal.pub.json` pins the seal public key and keyid. The private
seed lives outside every repository and is never printed, logged, or
transmitted.

## Honesty rules

- A skipped anything is named and counted, never silent
  (`provision_failed_specs`, the `execution_ref_v1[node]` optional-dep skip).
- `seal.py` refuses to seal a run that is not fully green.
- A receipt that fails any check is a hard failure, not a warning.
