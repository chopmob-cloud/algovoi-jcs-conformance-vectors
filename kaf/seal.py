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


def _pkg_version(name: str) -> str:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return "unknown"


def _canon(obj: dict) -> bytes:
    """Canonical bytes, with a real independent differential cross-check."""
    body = canonicalize_bytes(obj)
    if body != rfc8785.dumps(obj):
        raise SystemExit("FATAL: substrate and rfc8785 disagree on the bytes")
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
    ap.add_argument("--genesis-anchor", type=Path, default=None,
                    help="P0 MANIFEST file anchoring the first receipt")
    args = ap.parse_args()

    run_meta = json.loads((args.run_dir / "run_meta.json").read_text(encoding="utf-8"))
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
        cell_green = (overall == 0 and all(v == 0 for v in suites.values())
                      and not prov_failed and not degraded)
        if not cell_green:
            derived_green = False
        cells.append({
            "id": cid,
            "image": locked["image"],
            "image_digest": locked["digest"],
            "network": "none",
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

    rcpts = existing_receipts(args.receipts_dir)
    prev, prev_seq = previous_link(rcpts, args.genesis_anchor)
    seq = prev_seq + 1

    sealer = {
        "alg": "ed25519",
        "keyid": pub["keyid"],
        "canon_engine": "algovoi-substrate",
        "canon_engine_version": _pkg_version("algovoi-substrate"),
        "canon_cross_checks": ["rfc8785", "kaf/_jcs_min (independent)"],
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
        "artifacts": {"results_tree_sha256": tree_sha256(args.run_dir)},
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
    print(f"sealed {out.name} seq={seq} sha256={hashlib.sha256(env_bytes).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
