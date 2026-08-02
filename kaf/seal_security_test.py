#!/usr/bin/env python3
"""Adversarial security battery for the Keystone Seal receipt chain (v2).

Every attack below produces a chain that MUST be rejected by kaf_verify.py
(nonzero exit; crashes count as rejection). The untouched chain is the control
and MUST pass. Attacks run against copies in a temp dir; the real receipts are
never touched.

Attack classes:
  A1  bit flips at spread offsets in each receipt file
  A2  semantic field tampering re-serialized canonically (attacker owns a
      correct JCS implementation)
  A3  signature transplant between receipts
  A4  key substitution: attacker re-signs a tampered receipt with their own key
  A5  chain manipulation: drop the middle receipt; swap order
  A6  canonicalization confusion: semantically identical, non-canonical bytes
  A7  content-digest fixup with the original signature
  A8  wrong genesis anchor / missing anchor
  A9  seal stripping / unknown seal field
  A10 tail truncation: drop the newest receipt (caught by --expect-count)
  A11 totals forgery: flip a cell's overall to nonzero while all_green stays true
  A12 seq gap: renumber a receipt's sequence
  A13 provenance forgery: flip sealer.canon_cross_check_match to false
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from algovoi_substrate import canonicalize_bytes

HERE = Path(__file__).resolve().parent
VERIFY = HERE / "kaf_verify.py"

PASS = 0
FAIL = 0


def run_verify(receipts_dir: Path, pub_file: Path, genesis: Path | None,
               expect_count: int | None = None) -> int:
    cmd = [sys.executable, str(VERIFY), "--receipts-dir", str(receipts_dir),
           "--pub-file", str(pub_file)]
    if genesis is not None:
        cmd += ["--genesis-anchor", str(genesis)]
    if expect_count is not None:
        cmd += ["--expect-count", str(expect_count)]
    return subprocess.run(cmd, capture_output=True, text=True).returncode


def check(name: str, rejected: bool) -> None:
    global PASS, FAIL
    if rejected:
        PASS += 1
        print(f"  [REJECTED as required] {name}")
    else:
        FAIL += 1
        print(f"  [!!! ACCEPTED !!!]     {name}")


def fresh_copy(src: Path) -> Path:
    d = Path(tempfile.mkdtemp(prefix="kafsec-"))
    dst = d / "receipts"
    shutil.copytree(src, dst)
    return dst


def rewrite_canonical(path: Path, mutate) -> None:
    env = json.loads(path.read_bytes())
    mutate(env)
    path.write_bytes(canonicalize_bytes(env))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--receipts-dir", required=True, type=Path)
    ap.add_argument("--pub-file", required=True, type=Path)
    ap.add_argument("--genesis-anchor", required=True, type=Path)
    args = ap.parse_args()

    src, pub, gen = args.receipts_dir, args.pub_file, args.genesis_anchor
    rcpts = sorted(src.glob("rcpt-*.json"))
    n = len(rcpts)
    if n < 3:
        print("need a chain of at least 3 receipts to attack")
        return 2

    print("== control: untouched chain must verify ==")
    if run_verify(src, pub, gen, expect_count=n) != 0:
        print("  FATAL: control chain does not verify; aborting")
        return 2
    print("  [OK] control verifies")

    print("== A1: bit flips ==")
    for r in rcpts:
        raw = bytearray(r.read_bytes())
        for off in (1, len(raw) // 3, len(raw) // 2, len(raw) - 2):
            c = fresh_copy(src)
            t = bytearray(raw); t[off] ^= 0x01
            (c / r.name).write_bytes(bytes(t))
            check(f"{r.name} flip@{off}", run_verify(c, pub, gen, n) != 0)

    print("== A2: canonical field tampering ==")
    for field, mut in [
        ("run id renamed", lambda e: e["receipt"]["run"].__setitem__("id", "forged")),
        ("first cell image_digest swapped",
         lambda e: e["receipt"]["cells"][0].__setitem__("image_digest", "sha256:" + "0" * 64)),
        ("prev link redirected", lambda e: e["receipt"]["prev"].__setitem__("sha256", "0" * 64)),
        ("corpus commit swapped", lambda e: e["receipt"]["corpus"].__setitem__("commit", "f" * 40)),
        ("purpose reworded", lambda e: e["receipt"]["run"].__setitem__("purpose", "forged claim")),
    ]:
        c = fresh_copy(src)
        rewrite_canonical(c / rcpts[1].name, mut)
        check(f"A2 {field}", run_verify(c, pub, gen, n) != 0)

    print("== A3: signature transplant ==")
    c = fresh_copy(src)
    a = json.loads((c / rcpts[0].name).read_bytes())
    b = json.loads((c / rcpts[1].name).read_bytes())
    for k in ("signature", "signature_input", "content_digest", "created"):
        b["seal"][k] = a["seal"][k]
    (c / rcpts[1].name).write_bytes(canonicalize_bytes(b))
    check("A3 seal of receipt 1 transplanted onto receipt 2", run_verify(c, pub, gen, n) != 0)

    print("== A4: key substitution (attacker signs) ==")
    try:
        from nacl.signing import SigningKey
        from algovoi_rfc9421_signer import sign_request
        c = fresh_copy(src)
        target = c / rcpts[1].name
        env = json.loads(target.read_bytes())
        env["receipt"]["run"]["purpose"] = "forged by attacker key"
        body = canonicalize_bytes(env["receipt"])
        sig = sign_request(method=env["seal"]["method"], authority=env["seal"]["authority"],
                           path=env["seal"]["path"], body=body,
                           private_key=(b"\x42" * 32).hex(), keyid=env["seal"]["keyid"],
                           created=env["seal"]["created"])
        env["seal"]["signature"] = sig.signature
        env["seal"]["signature_input"] = sig.signature_input
        env["seal"]["content_digest"] = sig.content_digest
        env["seal"]["public_key_hex"] = SigningKey(b"\x42" * 32).verify_key.encode().hex()
        target.write_bytes(canonicalize_bytes(env))
        check("A4 attacker key + attacker pubkey in seal", run_verify(c, pub, gen, n) != 0)
    except ImportError:
        print("  (signer not installed here; A4 skipped)")

    print("== A5: chain manipulation ==")
    c = fresh_copy(src); (c / rcpts[1].name).unlink()
    check("A5 middle receipt dropped", run_verify(c, pub, gen) != 0)
    c = fresh_copy(src)
    b0, b1 = (c / rcpts[0].name).read_bytes(), (c / rcpts[1].name).read_bytes()
    (c / rcpts[0].name).write_bytes(b1); (c / rcpts[1].name).write_bytes(b0)
    check("A5 receipt order swapped", run_verify(c, pub, gen, n) != 0)

    print("== A6: canonicalization confusion ==")
    c = fresh_copy(src)
    env = json.loads((c / rcpts[1].name).read_bytes())
    (c / rcpts[1].name).write_text(json.dumps(env, indent=2), encoding="utf-8")
    check("A6 semantically identical, non-canonical bytes", run_verify(c, pub, gen, n) != 0)

    print("== A7: content-digest fixup ==")
    c = fresh_copy(src)
    env = json.loads((c / rcpts[1].name).read_bytes())
    env["receipt"]["run"]["purpose"] = "tampered with digest fixup"
    body = canonicalize_bytes(env["receipt"])
    d = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
    env["seal"]["content_digest"] = f"sha-256=:{d}:"
    (c / rcpts[1].name).write_bytes(canonicalize_bytes(env))
    check("A7 recomputed Content-Digest, original signature", run_verify(c, pub, gen, n) != 0)

    print("== A8: anchor attacks ==")
    wrong = Path(tempfile.mkdtemp(prefix="kafsec-")) / "wrong.txt"
    wrong.write_text("not the P0 manifest", encoding="utf-8")
    check("A8 wrong genesis anchor", run_verify(src, pub, wrong, n) != 0)
    check("A8 missing genesis anchor (mandatory)", run_verify(src, pub, None, n) != 0)

    print("== A9: seal shape attacks ==")
    c = fresh_copy(src)
    env = json.loads((c / rcpts[1].name).read_bytes())
    del env["seal"]["signature"]
    (c / rcpts[1].name).write_bytes(canonicalize_bytes(env))
    check("A9 signature field removed", run_verify(c, pub, gen, n) != 0)
    c = fresh_copy(src)
    env = json.loads((c / rcpts[1].name).read_bytes())
    env["seal"]["attacker_note"] = "extra"
    (c / rcpts[1].name).write_bytes(canonicalize_bytes(env))
    check("A9 unknown seal field added", run_verify(c, pub, gen, n) != 0)

    print("== A10: tail truncation ==")
    c = fresh_copy(src)
    (c / rcpts[-1].name).unlink()
    check("A10 newest receipt dropped (expect-count pins head)",
          run_verify(c, pub, gen, n) != 0)

    print("== A11: totals forgery ==")
    c = fresh_copy(src)
    rewrite_canonical(c / rcpts[1].name,
                      lambda e: e["receipt"]["cells"][0].__setitem__("overall", 5))
    check("A11 cell overall=5 while totals.all_green stays true",
          run_verify(c, pub, gen, n) != 0)

    print("== A12: seq gap ==")
    c = fresh_copy(src)
    rewrite_canonical(c / rcpts[1].name,
                      lambda e: e["receipt"].__setitem__("seq", 99))
    check("A12 receipt seq renumbered", run_verify(c, pub, gen, n) != 0)

    print("== A13: provenance forgery ==")
    c = fresh_copy(src)
    rewrite_canonical(c / rcpts[1].name,
                      lambda e: e["receipt"]["sealer"].__setitem__("canon_cross_check_match", False))
    check("A13 sealer.canon_cross_check_match flipped to false",
          run_verify(c, pub, gen, n) != 0)

    print("=" * 60)
    total = PASS + FAIL
    print(f"SEAL SECURITY BATTERY: {PASS}/{total} attacks rejected, {FAIL} accepted")
    if FAIL == 0:
        print("RESULT: GREEN (every forgery class rejected; control verifies)")
        return 0
    print("RESULT: FAILURES PRESENT")
    return 1


if __name__ == "__main__":
    sys.exit(main())
