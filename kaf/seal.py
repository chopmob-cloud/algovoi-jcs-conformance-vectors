#!/usr/bin/env python3
"""KAF sealer: build and sign a run receipt (the Keystone Seal), v2.

Consumes an orchestrated run directory (run_meta.json, cells.lock.json,
run_summary.json, results/) and emits a sealed receipt envelope into
kaf/receipts/.

Integrity properties (each closes a reviewed weakness):
  - The receipt body is JCS-canonical via algovoi-substrate, cross-checked
    byte-for-byte against a genuinely INDEPENDENT canonicalizer (kaf/_jcs_min,
    which shares no code with rfc8785/substrate). A divergence aborts the seal.
  - all_green and totals are RE-DERIVED from the per-cell evidence here, not
    trusted from the summary: a run with any nonzero cell overall/suite, any
    degraded cell, or any unpinned image digest is refused.
  - A monotonic seq is embedded in the SIGNED body, so a verifier that knows
    the expected count can detect tail-truncation of the chain.
  - Seal provenance (canon engine, signer package, keyid, alg) lives INSIDE
    the signed receipt body, so it cannot be altered on the chain head.

The private seal seed lives OUTSIDE the repository and is never printed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from importlib import metadata
from pathlib import Path

from algovoi_rfc9421_signer import sign_request
from algovoi_substrate import canonicalize_bytes
import rfc8785

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _jcs_min  # independent JCS, no shared code with rfc8785/substrate

AUTHORITY = "kaf.algovoi.co.uk"
PATH = "/kaf/receipt"
SCHEMA = "kaf-receipt-v2"


def _is_zero(x) -> bool:
    """A genuine zero return code. Rejects JSON booleans: `False == 0` is True in
    Python, so a boolean masquerading as a zero rc must NOT count as green (F-E)."""
    return isinstance(x, int) and not isinstance(x, bool) and x == 0


def _pkg_version(name: str) -> str:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return "unknown"


def _canon(obj: dict) -> bytes:
    """Canonical bytes with a genuinely independent differential cross-check.

    Independence note: algovoi-substrate delegates to rfc8785 (it IS rfc8785 plus
    type validation), so the substrate-vs-rfc8785 comparison below is a
    version-consistency self-check, NOT a second independent implementation. The
    one genuinely independent in-process check is _jcs_min (no shared code with
    rfc8785/substrate). Cross-implementation independence at scale is the P3
    10-language differential consensus, not this in-process pair."""
    body = canonicalize_bytes(obj)
    if body != rfc8785.dumps(obj):
        raise SystemExit("FATAL: substrate and its rfc8785 backend disagree (version skew)")
    if body != _jcs_min.dumps(obj):
        raise SystemExit("FATAL: independent JCS (_jcs_min) disagrees on the bytes")
    return body


def tree_sha256(run_dir: Path) -> str:
    lines = []
    for p in sorted(run_dir.rglob("*")):
        if p.is_dir():
            continue
        rel = p.relative_to(run_dir).as_posix()
        if rel.startswith("cellenv/"):
            continue
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        lines.append(f"{rel}\n{h}\n")
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def _artifacts(run_dir: Path, run_meta: dict) -> dict:
    """Signed artifacts block. Records the results tree hash always, and — for a
    report-attestation wrap — the bound report + the verdict it was gated on, so
    a verifier holding the evidence can re-derive correctness (F1)."""
    art = {"results_tree_sha256": tree_sha256(run_dir),
           "evidence_kind": run_meta.get("evidence_kind", "cell-execution")}
    if run_meta.get("attested_report"):
        art["attested_report"] = run_meta["attested_report"]
    if "attested_verdict" in run_meta:
        art["attested_verdict"] = run_meta["attested_verdict"]
    return art


def existing_receipts(receipts_dir: Path) -> list[Path]:
    return sorted(receipts_dir.glob("rcpt-*.json"))


def previous_link(rcpts: list[Path], genesis_anchor: Path | None) -> tuple[dict, int]:
    if rcpts:
        prev_env = json.loads(rcpts[-1].read_bytes())
        prev_seq = prev_env["receipt"]["seq"]
        return ({"kind": "receipt", "name": rcpts[-1].name,
                 "sha256": hashlib.sha256(rcpts[-1].read_bytes()).hexdigest()},
                prev_seq)
    if genesis_anchor is None:
        raise SystemExit("no prior receipt and no --genesis-anchor given")
    return ({"kind": "p0-manifest", "name": genesis_anchor.name,
             "sha256": hashlib.sha256(genesis_anchor.read_bytes()).hexdigest()}, 0)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True, type=Path)
    ap.add_argument("--receipts-dir", required=True, type=Path)
    ap.add_argument("--seed-file", required=True, type=Path,
                    help="hex Ed25519 seed, outside the repo, never printed")
    ap.add_argument("--pub-file", required=True, type=Path,
                    help="pinned public key registry (kaf/keys/kaf-seal.pub.json)")
    ap.add_argument("--purpose", required=True)
    ap.add_argument("--evidence-kind", choices=["cell-execution", "report-attestation"],
                    default="cell-execution",
                    help="operator-asserted run kind (F-B). report-attestation skips the "
                         "F5 --network=none argv check; intent comes from THIS flag, never "
                         "from the untrusted run-dir.")
    ap.add_argument("--genesis-anchor", type=Path, default=None,
                    help="P0 MANIFEST file anchoring the first receipt")
    args = ap.parse_args()

    run_meta = json.loads((args.run_dir / "run_meta.json").read_text(encoding="utf-8"))
    # F-B: the flag that disables the isolation gate is operator intent from the
    # CLI, not a value read from the untrusted run-dir. Cross-check: if the
    # evidence claims a different kind than the operator asserted, refuse rather
    # than silently trusting evidence to turn a security gate off.
    is_attestation = args.evidence_kind == "report-attestation"
    meta_kind = run_meta.get("evidence_kind", "cell-execution")
    if meta_kind != args.evidence_kind:
        print(f"REFUSING to seal: --evidence-kind {args.evidence_kind} disagrees with "
              f"run_meta evidence_kind {meta_kind!r}", file=sys.stderr)
        return 2
    lock = json.loads((args.run_dir / "cells.lock.json").read_text(encoding="utf-8"))
    summary = json.loads((args.run_dir / "run_summary.json").read_text(encoding="utf-8"))
    pub = json.loads(args.pub_file.read_text(encoding="utf-8"))
    seed_hex = args.seed_file.read_text(encoding="utf-8").strip()

    # Re-derive greenness from the evidence; do not trust summary.all_green.
    cells = []
    derived_green = True
    for cid, c in sorted(summary["cells"].items()):
        locked = next((l for l in lock["locked"] if l["cell"] == cid), None)
        if locked is None or not locked.get("digest"):
            print(f"REFUSING to seal: cell {cid} has no pinned image digest",
                  file=sys.stderr)
            return 2
        overall = c.get("overall")
        suites = {k: int(v) for k, v in sorted(c.get("suites", {}).items())}
        prov_failed = [s for s in c.get("provision_failed_specs", []) if s]
        degraded = c.get("degraded", [])

        # F2: do NOT trust the aggregated run_summary.json. Re-parse the raw
        # per-cell suites.tsv and require the summary to match it exactly, so a
        # tampered or buggy aggregation that claims green over red raw evidence
        # is refused. (The raw file was already tree-bound; now it is also the
        # source of truth for the sealed greenness.)
        raw_tsv = args.run_dir / "results" / cid / "suites.tsv"
        if not raw_tsv.exists():
            print(f"REFUSING to seal: cell {cid} has no raw suites.tsv to cross-check",
                  file=sys.stderr)
            return 2
        raw_overall, raw_suites = None, {}
        for line in raw_tsv.read_text(encoding="utf-8").splitlines():
            if not line or "\t" not in line:
                continue
            name, _, rc = line.partition("\t")
            try:
                rc = int(rc)
            except ValueError:
                print(f"REFUSING to seal: cell {cid} suites.tsv has a non-integer rc "
                      f"({name!r})", file=sys.stderr)
                return 2
            if name == "overall":
                raw_overall = rc
            else:
                raw_suites[name] = rc
        if raw_overall != overall or raw_suites != suites:
            print(f"REFUSING to seal: cell {cid} run_summary disagrees with raw suites.tsv "
                  f"(summary overall={overall} suites={suites}; "
                  f"raw overall={raw_overall} suites={raw_suites})", file=sys.stderr)
            return 2

        # F5: for a real cell execution the exec docker argv MUST record
        # --network=none, so isolation is proven-recorded rather than assumed.
        # (Skipped for report-attestation wraps, whose isolation lived in the
        # underlying run they attest.)
        if not is_attestation:
            argv_f = args.run_dir / "results" / cid / "docker_argv_exec.txt"
            if not argv_f.exists() or "--network=none" not in argv_f.read_text(encoding="utf-8"):
                print(f"REFUSING to seal: cell {cid} exec argv does not record "
                      f"--network=none (isolation unproven)", file=sys.stderr)
                return 2

        cell_green = (_is_zero(overall) and all(_is_zero(v) for v in suites.values())
                      and not prov_failed and not degraded)
        if not cell_green:
            derived_green = False
        cells.append({
            "id": cid,
            "image": locked["image"],
            "image_digest": locked["digest"],
            "network": ("none" if not is_attestation else "upstream-attested"),
            "canary": c.get("canary"),
            "suites": suites,
            "overall": overall,
            "provision_failed_specs": prov_failed,
            "degraded": degraded,
        })

    if not derived_green:
        print("REFUSING to seal: re-derived greenness is false (a cell is not "
              "fully green). summary.all_green is NOT trusted.", file=sys.stderr)
        return 2
    if not cells:
        print("REFUSING to seal: no cells in the run", file=sys.stderr)
        return 2

    # F-A: a run that declares a differential N-way consensus (P3) must carry it
    # GREEN and BOUND into the per-cell evidence. run_meta.consensus_rc is only
    # advisory (untrusted); the authoritative form is a per-cell 'consensus' suite
    # (already folded into cell greenness above by orchestrate_p3). Refuse a
    # consensus-declaring run that is not bound, so a hash-split run whose cells
    # each individually "ran fine" can never seal as a green consensus.
    if "consensus_rc" in run_meta:
        if run_meta.get("consensus_rc") != 0:
            print("REFUSING to seal: run declares consensus_rc != 0 (N-way consensus failed)",
                  file=sys.stderr)
            return 2
        missing_bind = [c["id"] for c in cells if "consensus" not in c["suites"]]
        if missing_bind:
            print(f"REFUSING to seal: consensus-declaring run has cells without a bound "
                  f"'consensus' suite (unbound consensus): {missing_bind}", file=sys.stderr)
            return 2

    rcpts = existing_receipts(args.receipts_dir)
    prev, prev_seq = previous_link(rcpts, args.genesis_anchor)
    seq = prev_seq + 1

    sealer = {
        "alg": "ed25519",
        "keyid": pub["keyid"],
        "canon_engine": "algovoi-substrate",
        "canon_engine_version": _pkg_version("algovoi-substrate"),
        "canon_cross_checks": ["rfc8785 (substrate's own backend; version-consistency check)",
                               "kaf/_jcs_min (independent, no shared code)"],
        "canon_cross_check_match": True,
        "signer_pkg": f"algovoi-rfc9421-signer=={_pkg_version('algovoi-rfc9421-signer')}",
        "verifier_target": "algovoi-rfc9421-verifier>=0.3.3",
    }

    receipt = {
        "schema": SCHEMA,
        "seq": seq,
        "framework": {"name": "KAF", "version": "0.2.0",
                      "design": "keystone-assurance-framework-v1"},
        "run": {"id": run_meta["run_id"], "purpose": args.purpose,
                "host": run_meta["host"], "started": run_meta["started"],
                "finished": run_meta["finished"]},
        "corpus": {"repo": "algovoi-jcs-conformance-vectors",
                   "commit": run_meta["corpus_commit"],
                   "branch": run_meta["corpus_branch"]},
        "cells": cells,
        "totals": {"cells": len(cells),
                   "suite_executions": sum(len(c["suites"]) for c in cells),
                   "all_green": True},
        "sealer": sealer,
        # F1: distinguish a real hermetic cell execution from a report-attestation
        # (wrap_report_run.py). A report-attestation's suite=0 is a wrapper-asserted
        # value, not a re-derivable cell result, so it is labelled here (signed) and
        # its bound report + verdict are recorded, so a verifier with the evidence
        # can re-derive correctness rather than trust the wrapper's greenness.
        "artifacts": _artifacts(args.run_dir, run_meta),
        "prev": prev,
    }

    body = _canon(receipt)
    created = int(time.time())
    sig = sign_request(method="POST", authority=AUTHORITY, path=PATH,
                       body=body, private_key=seed_hex,
                       keyid=pub["keyid"], created=created)

    envelope = {
        "receipt": receipt,
        "seal": {
            "keyid": pub["keyid"],
            "public_key_hex": pub["public_key_hex"],
            "created": created,
            "method": "POST", "authority": AUTHORITY, "path": PATH,
            "content_digest": sig.content_digest,
            "signature_input": sig.signature_input,
            "signature": sig.signature,
        },
    }

    # Number by max existing index + 1 (never by count, which collides after a
    # deletion), pad wide enough to keep lexicographic order.
    max_idx = 0
    for r in rcpts:
        m = re.match(r"rcpt-(\d+)-", r.name)
        if m:
            max_idx = max(max_idx, int(m.group(1)))
    n = max_idx + 1
    safe_run = re.sub(r"[^A-Za-z0-9_.-]", "_", run_meta["run_id"])
    out = args.receipts_dir / f"rcpt-{n:06d}-{safe_run}.json"
    args.receipts_dir.mkdir(parents=True, exist_ok=True)
    env_bytes = _canon(envelope)
    out.write_bytes(env_bytes)
    head_sha = hashlib.sha256(env_bytes).hexdigest()
    # F4: record the chain head (count + head sha) so an operator can pin it out
    # of band for kaf_verify --expect-count/--expect-head.
    n_total = len(existing_receipts(args.receipts_dir))
    (args.receipts_dir / "CHAIN_HEAD.txt").write_text(
        f"count={n_total}\nhead={out.name}\nhead_sha256={head_sha}\n", encoding="utf-8")
    print(f"sealed {out.name} seq={seq} sha256={head_sha}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
