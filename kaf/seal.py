#!/usr/bin/env python3
"""KAF sealer: build and sign a run receipt (the Keystone Seal).

Consumes an orchestrated run directory (run_meta.json, cells.lock.json,
run_summary.json, results/) and emits a sealed receipt envelope into
kaf/receipts/. The receipt body is JCS-canonical via algovoi-substrate's
canonicalize_bytes, cross-checked byte-for-byte against the independent
rfc8785 implementation (a differential check inside the sealer itself).
The seal is an RFC 9421 signature over a synthetic HTTP message whose body
is the canonical receipt, produced by the published algovoi-rfc9421-signer
and verifiable offline by the published algovoi-rfc9421-verifier.

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

AUTHORITY = "kaf.algovoi.co.uk"
PATH = "/kaf/receipt"
SCHEMA = "kaf-receipt-v1"


def _pkg_version(name: str) -> str:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return "unknown"


def tree_sha256(run_dir: Path) -> str:
    """Digest of the run evidence tree: sorted relpath + file sha256 lines.
    The cellenv/ tree (interpreter environments) is provenance, not evidence,
    and is excluded; provision records are copied into results/ by run_cell."""
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


def previous_link(receipts_dir: Path, genesis_anchor: Path | None) -> dict:
    rcpts = sorted(receipts_dir.glob("rcpt-*.json"))
    if rcpts:
        return {"kind": "receipt",
                "name": rcpts[-1].name,
                "sha256": hashlib.sha256(rcpts[-1].read_bytes()).hexdigest()}
    if genesis_anchor is None:
        raise SystemExit("no prior receipt and no --genesis-anchor given")
    return {"kind": "p0-manifest",
            "name": genesis_anchor.name,
            "sha256": hashlib.sha256(genesis_anchor.read_bytes()).hexdigest()}


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

    if not summary.get("all_green", False):
        print("REFUSING to seal: run_summary.all_green is false", file=sys.stderr)
        return 2

    cells = []
    for cid, c in sorted(summary["cells"].items()):
        locked = next((l for l in lock["locked"] if l["cell"] == cid), None)
        cells.append({
            "id": cid,
            "image": locked["image"] if locked else "unknown",
            "image_digest": locked["digest"] if locked else "unknown",
            "network": "none",
            "canary": c.get("canary"),
            "suites": {k: v for k, v in sorted(c["suites"].items())},
            "overall": c["overall"],
            "provision_failed_specs":
                (c.get("provision") or {}).get("failed_specs", []),
        })

    receipt = {
        "schema": SCHEMA,
        "framework": {"name": "KAF", "version": "0.1.0",
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
        "artifacts": {"results_tree_sha256": tree_sha256(args.run_dir)},
        "prev": previous_link(args.receipts_dir, args.genesis_anchor),
    }

    body = canonicalize_bytes(receipt)
    cross = rfc8785.dumps(receipt)
    if body != cross:
        print("FATAL: substrate JCS and rfc8785 disagree on the receipt bytes",
              file=sys.stderr)
        return 3

    created = int(time.time())
    sig = sign_request(method="POST", authority=AUTHORITY, path=PATH,
                       body=body, private_key=seed_hex,
                       keyid=pub["keyid"], created=created)

    envelope = {
        "receipt": receipt,
        "seal": {
            "alg": "ed25519",
            "keyid": pub["keyid"],
            "public_key_hex": pub["public_key_hex"],
            "created": created,
            "method": "POST", "authority": AUTHORITY, "path": PATH,
            "content_digest": sig.content_digest,
            "signature_input": sig.signature_input,
            "signature": sig.signature,
            "canon": {"engine": "algovoi-substrate",
                      "engine_version": _pkg_version("algovoi-substrate"),
                      "cross_check": "rfc8785",
                      "cross_check_version": _pkg_version("rfc8785"),
                      "match": True},
            "signer_pkg": f"algovoi-rfc9421-signer=={_pkg_version('algovoi-rfc9421-signer')}",
            "verifier_target": "algovoi-rfc9421-verifier>=0.3.3",
        },
    }

    n = len(list(args.receipts_dir.glob("rcpt-*.json"))) + 1
    safe_run = re.sub(r"[^A-Za-z0-9_.-]", "_", run_meta["run_id"])
    out = args.receipts_dir / f"rcpt-{n:04d}-{safe_run}.json"
    args.receipts_dir.mkdir(parents=True, exist_ok=True)
    env_bytes = canonicalize_bytes(envelope)
    out.write_bytes(env_bytes)
    print(f"sealed {out.name} sha256={hashlib.sha256(env_bytes).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
