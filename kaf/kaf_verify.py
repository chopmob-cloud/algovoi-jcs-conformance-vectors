#!/usr/bin/env python3
"""kaf-verify: offline verification of Keystone Seal receipts.

For each receipt envelope, entirely offline:
  1. the envelope file bytes must BE the JCS-canonical form of the envelope
     (any reformatting or edit breaks this),
  2. the receipt body's canonical bytes are recomputed with algovoi-substrate
     and cross-checked against the independent rfc8785 implementation,
  3. the RFC 9530 Content-Digest in the seal must match those bytes,
  4. the RFC 9421 Ed25519 signature must verify via the PUBLISHED
     algovoi-rfc9421-verifier (the stack under test is the stack that proves
     the results),
  5. the seal key must match the pinned registry (kaf/keys/kaf-seal.pub.json),
  6. each receipt's prev.sha256 must equal the sha256 of the previous
     envelope file (hash chain), with the first anchored to the P0 MANIFEST
     when --genesis-anchor is supplied.

Exit 0 iff every check on every receipt passes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from algovoi_rfc9421_verifier import verify_request
from algovoi_substrate import canonicalize_bytes
import rfc8785


def fail(msg: str) -> None:
    print(f"  FAIL: {msg}")


def verify_one(path: Path, pub: dict, prev_file: Path | None,
               genesis_anchor: Path | None) -> bool:
    raw = path.read_bytes()
    env = json.loads(raw)
    ok = True

    if canonicalize_bytes(env) != raw:
        fail("envelope file is not in JCS-canonical byte form (modified?)")
        ok = False

    receipt, seal = env["receipt"], env["seal"]
    body = canonicalize_bytes(receipt)
    if rfc8785.dumps(receipt) != body:
        fail("substrate and rfc8785 disagree on receipt canonical bytes")
        ok = False

    if seal["keyid"] != pub["keyid"] or seal["public_key_hex"] != pub["public_key_hex"]:
        fail("seal key does not match the pinned key registry")
        ok = False
    if f'keyid="{pub["keyid"]}"' not in seal["signature_input"]:
        fail("pinned keyid absent from signature_input")
        ok = False

    res = verify_request(
        method=seal["method"], authority=seal["authority"], path=seal["path"],
        headers={"content-digest": seal["content_digest"],
                 "signature-input": seal["signature_input"],
                 "signature": seal["signature"]},
        body=body, public_key=seal["public_key_hex"], mode="rfc9421")
    if not res.valid:
        for e in res.errors:
            fail(f"verifier: {e}")
        ok = False

    prev = receipt["prev"]
    if prev_file is not None:
        want = hashlib.sha256(prev_file.read_bytes()).hexdigest()
        if prev["kind"] != "receipt" or prev["sha256"] != want:
            fail(f"chain break: prev.sha256 != sha256({prev_file.name})")
            ok = False
    elif genesis_anchor is not None:
        want = hashlib.sha256(genesis_anchor.read_bytes()).hexdigest()
        if prev["kind"] != "p0-manifest" or prev["sha256"] != want:
            fail("genesis receipt is not anchored to the supplied P0 manifest")
            ok = False

    green = receipt["totals"]["all_green"] is True
    if not green:
        fail("receipt totals.all_green is not true")
        ok = False

    state = "OK " if ok else "BAD"
    print(f"[{state}] {path.name} run={receipt['run']['id']} "
          f"cells={receipt['totals']['cells']} "
          f"suites={receipt['totals']['suite_executions']} "
          f"sha256={hashlib.sha256(raw).hexdigest()[:16]}..")
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--receipts-dir", required=True, type=Path)
    ap.add_argument("--pub-file", required=True, type=Path)
    ap.add_argument("--genesis-anchor", type=Path, default=None)
    args = ap.parse_args()

    pub = json.loads(args.pub_file.read_text(encoding="utf-8"))
    rcpts = sorted(args.receipts_dir.glob("rcpt-*.json"))
    if not rcpts:
        print("no receipts found")
        return 2

    all_ok = True
    prev: Path | None = None
    for r in rcpts:
        all_ok &= verify_one(r, pub, prev, args.genesis_anchor)
        prev = r
    print(f"CHAIN: {len(rcpts)} receipt(s) "
          + ("VERIFIED (offline, published verifier)" if all_ok else "FAILED"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
