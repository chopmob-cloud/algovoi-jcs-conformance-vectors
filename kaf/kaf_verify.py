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
import os
import re
import sys
from pathlib import Path

from algovoi_rfc9421_verifier import verify_request
from algovoi_substrate import canonicalize_bytes
import rfc8785

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _jcs_min

def _is_zero(x) -> bool:
    """Genuine zero rc; rejects JSON booleans (`False == 0` is True in Python), so
    a boolean masquerading as a zero cannot re-derive as green (F-E)."""
    return isinstance(x, int) and not isinstance(x, bool) and x == 0


_TOP_KEYS = {"receipt", "seal"}
_SEAL_KEYS = {"keyid", "public_key_hex", "created", "method", "authority",
              "path", "content_digest", "signature_input", "signature"}
_RECEIPT_KEYS = {"schema", "seq", "framework", "run", "corpus", "cells",
                 "totals", "sealer", "artifacts", "prev"}
# v3 adds a hash-bound coverage catalog and an in-cell-canary attestation.
_RECEIPT_KEYS_V3 = _RECEIPT_KEYS | {"catalog", "attestations"}
_SCHEMAS = {"kaf-receipt-v2", "kaf-receipt-v3"}


def _canon(obj) -> bytes:
    b = canonicalize_bytes(obj)
    if b != rfc8785.dumps(obj) or b != _jcs_min.dumps(obj):
        raise ValueError("canonicalizers disagree on the bytes")
    return b


def _tree_sha256(run_dir: Path) -> str:
    """Recompute a run dir's results-tree hash exactly as seal.py does (cellenv/
    excluded), so an evidence-bearing verify can confirm the SIGNED
    results_tree_sha256 against the actual harvested evidence (F1)."""
    lines = []
    for p in sorted(run_dir.rglob("*")):
        if p.is_dir():
            continue
        rel = p.relative_to(run_dir).as_posix()
        if rel.startswith("cellenv/"):
            continue
        lines.append(f"{rel}\n{hashlib.sha256(p.read_bytes()).hexdigest()}\n")
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def recheck_evidence(receipt: dict, evidence_dir: Path) -> list[str]:
    """F1: with the evidence present, re-derive CORRECTNESS (not just
    authenticity). Find the run dir whose results-tree hash matches the signed
    artifacts.results_tree_sha256; for a report-attestation, re-read the bound
    report and confirm its verdict matches what was sealed."""
    errs = []
    art = receipt.get("artifacts", {})
    want = art.get("results_tree_sha256")
    if not want:
        return ["receipt has no results_tree_sha256 to re-check"]
    match_dir = None
    for d in sorted(p for p in evidence_dir.iterdir() if p.is_dir()):
        try:
            if _tree_sha256(d) == want:
                match_dir = d
                break
        except OSError:
            continue
    if match_dir is None:
        return [f"no run dir under {evidence_dir} reproduces the sealed tree hash {want[:16]}.."]
    if art.get("evidence_kind") == "report-attestation":
        rep_name = art.get("attested_report")
        verdict = art.get("attested_verdict", {})
        rep_path = next(match_dir.rglob(rep_name), None) if rep_name else None
        if rep_path is None:
            errs.append(f"attested report {rep_name} not found in the matched evidence")
        else:
            rep = json.loads(rep_path.read_text(encoding="utf-8"))
            for k, v in verdict.items():
                if rep.get(k) != v:
                    errs.append(f"attested_verdict mismatch: report[{k}]={rep.get(k)} != sealed {v}")
    return errs


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
        schema = receipt.get("schema")
        if schema not in _SCHEMAS:
            errs.append(f"unknown receipt schema {schema!r}")
        expected_rkeys = _RECEIPT_KEYS_V3 if schema == "kaf-receipt-v3" else _RECEIPT_KEYS
        if set(receipt) != expected_rkeys:
            errs.append(f"unexpected receipt keys: {sorted(set(receipt) ^ expected_rkeys)}")
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
        # Match the created PARAMETER exactly (delimiter-bounded), not as a loose
        # substring: 'created=178' must NOT satisfy 'created=1785779139'. The
        # signature is authoritative over created; this is a strict sanity
        # cross-check on the envelope's echoed value (F7).
        if not re.search(rf'(?:^|;)created={seal["created"]}(?=;|$)', si):
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
            _is_zero(c.get("overall"))
            and all(_is_zero(v) for v in c.get("suites", {}).values())
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

        # (5b) v3: the coverage catalog must be a SUBSET of the tested cells
        # (coverage cannot be trimmed below what the catalog declares), and if the
        # receipt attests in-cell canaries, every cell must carry a passing one.
        # The catalog + attestation are inside the signed body, so they are already
        # tamper-evident; here we re-derive the PROPERTIES they assert.
        if schema == "kaf-receipt-v3":
            cat_cells = set(receipt.get("catalog", {}).get("cells", []))
            if not cat_cells:
                errs.append("v3 receipt has an empty catalog.cells")
            have = {c.get("id") for c in cells}
            missing = sorted(cat_cells - have)
            if missing:
                errs.append(f"v3 catalog not covered by cells[] (coverage trimmed): {missing}")
            if receipt.get("attestations", {}).get("in_cell_canary") is True:
                no_canary = sorted(str(c.get("id")) for c in cells
                                   if not _is_zero(c.get("suites", {}).get("canary")))
                if no_canary:
                    errs.append(f"v3 attests in_cell_canary but these cells lack a passing "
                                f"canary suite: {no_canary}")

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
    ap.add_argument("--evidence-dir", type=Path, default=None,
                    help="re-derive CORRECTNESS: confirm each receipt's signed tree "
                         "hash against the harvested run dirs, and re-check "
                         "report-attestation verdicts against the bound report")
    ap.add_argument("--allow-unpinned", action="store_true",
                    help="permit verification with NO head pin (tail truncation "
                         "becomes undetectable; off by default, F4)")
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
        try:
            receipt = json.loads(r.read_bytes()).get("receipt", {})
        except Exception:
            receipt = {}
        kind = receipt.get("artifacts", {}).get("evidence_kind", "cell-execution")
        if args.evidence_dir is not None and ok:
            ev_errs = recheck_evidence(receipt, args.evidence_dir)
            errs += ev_errs
            if ev_errs:
                ok = False
        tag = "  [attestation-only]" if kind == "report-attestation" else ""
        if args.evidence_dir is not None and not errs:
            tag += "  [evidence re-derived]"
        state = "OK " if ok else "BAD"
        print(f"[{state}] {r.name} sha256={hashlib.sha256(r.read_bytes()).hexdigest()[:16]}..{tag}")
        for e in errs:
            print(f"    - {e}")
        all_ok &= ok
        prev = r

    # F4: a trust decision REQUIRES a head pin. Without --expect-count/--expect-head
    # the newest receipt(s) could be silently truncated and the chain still reads
    # 1..N contiguous. Fail closed unless the operator explicitly waives it.
    pinned = args.expect_count is not None or args.expect_head is not None
    if args.expect_count is not None and len(rcpts) != args.expect_count:
        print(f"HEAD PIN FAIL: found {len(rcpts)} receipts, expected {args.expect_count}")
        all_ok = False
    if args.expect_head is not None:
        head = hashlib.sha256(rcpts[-1].read_bytes()).hexdigest()
        if head != args.expect_head:
            print(f"HEAD PIN FAIL: head sha256 {head} != expected {args.expect_head}")
            all_ok = False
    if not pinned and not args.allow_unpinned:
        print("HEAD UNPINNED (F4): no --expect-count/--expect-head supplied; tail "
              "truncation is undetectable. Re-run with a head pin, or pass "
              "--allow-unpinned to waive explicitly.")
        all_ok = False

    print(f"CHAIN: {len(rcpts)} receipt(s) "
          + ("VERIFIED (offline, published verifier)" if all_ok else "FAILED"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
