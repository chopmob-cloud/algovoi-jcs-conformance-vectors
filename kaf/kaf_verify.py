#!/usr/bin/env python3
"""kaf-verify: offline verification of Keystone Seal receipts (v2).

Entirely offline, for each receipt envelope:
  1. the envelope file bytes must BE the JCS-canonical form of the envelope,
     confirmed with algovoi-substrate AND an independent canonicalizer
     (kaf/_jcs_min) that shares no code with it;
  2. the receipt body's canonical bytes are recomputed the same way;
  3. the envelope is STRICTLY shaped: no unknown top-level/seal keys, and the
     seal's keyid/created/method/authority/path agree with the signed
     signature_input and with the receipt's own signed sealer block;
  4. the RFC 9421 Ed25519 signature verifies via the PUBLISHED
     algovoi-rfc9421-verifier and the key matches the pinned registry;
  5. greenness and totals are RE-DERIVED from cells[] and must match the
     stored values (the verifier never trusts totals.all_green);
  6. the hash chain holds AND the seq numbers are 1..N contiguous, so a
     dropped tail receipt is detectable; the genesis link is checked against
     the P0 manifest, and a genesis receipt with no anchor supplied FAILS
     (the anchor is not optional);
  7. optional --expect-count / --expect-head pin the chain head out of band.

A malformed receipt fails only itself (fails closed), never crashes the run.
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _jcs_min

_TOP_KEYS = {"receipt", "seal"}
_SEAL_KEYS = {"keyid", "public_key_hex", "created", "method", "authority",
              "path", "content_digest", "signature_input", "signature"}
_RECEIPT_KEYS = {"schema", "seq", "framework", "run", "corpus", "cells",
                 "totals", "sealer", "artifacts", "prev"}


def _canon(obj) -> bytes:
    b = canonicalize_bytes(obj)
    if b != rfc8785.dumps(obj) or b != _jcs_min.dumps(obj):
        raise ValueError("canonicalizers disagree on the bytes")
    return b


def verify_one(path: Path, pub: dict, prev_file: Path | None,
               genesis_anchor: Path | None, expected_seq: int) -> tuple[bool, list[str]]:
    errs: list[str] = []
    try:
        raw = path.read_bytes()
        env = json.loads(raw)
    except Exception as e:
        return False, [f"unreadable/invalid json: {e}"]

    try:
        # (1)(3) strict shape + canonical-byte identity
        if set(env) != _TOP_KEYS:
            errs.append(f"unexpected top-level keys: {sorted(set(env) ^ _TOP_KEYS)}")
        receipt, seal = env.get("receipt", {}), env.get("seal", {})
        if set(seal) != _SEAL_KEYS:
            errs.append(f"unexpected seal keys: {sorted(set(seal) ^ _SEAL_KEYS)}")
        if set(receipt) != _RECEIPT_KEYS:
            errs.append(f"unexpected receipt keys: {sorted(set(receipt) ^ _RECEIPT_KEYS)}")
        if errs:
            return False, errs

        if _canon(env) != raw:
            errs.append("envelope file is not in JCS-canonical byte form (modified?)")
        body = _canon(receipt)

        # (3) seal params must agree with the signed body / signature_input
        si = seal["signature_input"]
        sealer = receipt["sealer"]
        if seal["keyid"] != pub["keyid"] or seal["public_key_hex"] != pub["public_key_hex"]:
            errs.append("seal key does not match the pinned key registry")
        if sealer["keyid"] != pub["keyid"]:
            errs.append("signed sealer.keyid does not match the pinned registry")
        if f'keyid="{pub["keyid"]}"' not in si:
            errs.append("pinned keyid absent from signature_input")
        if f'created={seal["created"]}' not in si:
            errs.append("seal.created does not match the signed signature_input")
        if seal["method"] != "POST" or seal["authority"] != "kaf.algovoi.co.uk" \
                or seal["path"] != "/kaf/receipt":
            errs.append("seal method/authority/path deviate from the fixed values")

        # (4) signature via the published verifier
        res = verify_request(
            method=seal["method"], authority=seal["authority"], path=seal["path"],
            headers={"content-digest": seal["content_digest"],
                     "signature-input": si, "signature": seal["signature"]},
            body=body, public_key=seal["public_key_hex"], mode="rfc9421")
        if not res.valid:
            errs += [f"verifier: {e}" for e in res.errors]

        # (5) re-derive greenness + totals from cells; never trust the stored flag
        cells = receipt["cells"]
        derived_green = all(
            c.get("overall") == 0
            and all(v == 0 for v in c.get("suites", {}).values())
            and not c.get("provision_failed_specs")
            and not c.get("degraded")
            for c in cells
        )
        if not derived_green:
            errs.append("re-derived greenness is false but the receipt was sealed")
        if receipt["totals"].get("all_green") is not True:
            errs.append("totals.all_green is not true")
        if receipt["totals"].get("cells") != len(cells):
            errs.append("totals.cells disagrees with len(cells)")
        if receipt["totals"].get("suite_executions") != sum(len(c.get("suites", {})) for c in cells):
            errs.append("totals.suite_executions disagrees with cells")
        if sealer.get("canon_cross_check_match") is not True:
            errs.append("sealer.canon_cross_check_match is not true")

        # (6) seq contiguity + chain link + genesis anchor
        if receipt.get("seq") != expected_seq:
            errs.append(f"seq {receipt.get('seq')} != expected {expected_seq} (gap/truncation)")
        prev = receipt["prev"]
        if prev_file is not None:
            want = hashlib.sha256(prev_file.read_bytes()).hexdigest()
            if prev.get("kind") != "receipt" or prev.get("sha256") != want:
                errs.append(f"chain break: prev.sha256 != sha256({prev_file.name})")
        else:
            # first receipt: must be genesis-anchored, and the anchor is required
            if prev.get("kind") != "p0-manifest":
                errs.append("first receipt is not genesis-anchored (prev.kind != p0-manifest)")
            elif genesis_anchor is None:
                errs.append("genesis receipt present but no --genesis-anchor supplied (anchor is mandatory)")
            else:
                want = hashlib.sha256(genesis_anchor.read_bytes()).hexdigest()
                if prev.get("sha256") != want:
                    errs.append("genesis prev.sha256 does not match the supplied P0 manifest")
    except Exception as e:
        return False, errs + [f"exception during verify: {e}"]

    return (not errs), errs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--receipts-dir", required=True, type=Path)
    ap.add_argument("--pub-file", required=True, type=Path)
    ap.add_argument("--genesis-anchor", type=Path, default=None)
    ap.add_argument("--expect-count", type=int, default=None,
                    help="assert exactly this many receipts (pins the chain head)")
    ap.add_argument("--expect-head", default=None,
                    help="assert the newest receipt file has this sha256")
    args = ap.parse_args()

    pub = json.loads(args.pub_file.read_text(encoding="utf-8"))
    rcpts = sorted(args.receipts_dir.glob("rcpt-*.json"))
    if not rcpts:
        print("no receipts found")
        return 2

    all_ok = True
    prev: Path | None = None
    for i, r in enumerate(rcpts, start=1):
        ok, errs = verify_one(r, pub, prev, args.genesis_anchor, i)
        state = "OK " if ok else "BAD"
        print(f"[{state}] {r.name} sha256={hashlib.sha256(r.read_bytes()).hexdigest()[:16]}..")
        for e in errs:
            print(f"    - {e}")
        all_ok &= ok
        prev = r

    # Out-of-band head pins (defend against tail truncation).
    if args.expect_count is not None and len(rcpts) != args.expect_count:
        print(f"HEAD PIN FAIL: found {len(rcpts)} receipts, expected {args.expect_count}")
        all_ok = False
    if args.expect_head is not None:
        head = hashlib.sha256(rcpts[-1].read_bytes()).hexdigest()
        if head != args.expect_head:
            print(f"HEAD PIN FAIL: head sha256 {head} != expected {args.expect_head}")
            all_ok = False

    print(f"CHAIN: {len(rcpts)} receipt(s) "
          + ("VERIFIED (offline, published verifier)" if all_ok else "FAILED"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
