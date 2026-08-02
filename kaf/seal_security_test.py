#!/usr/bin/env python3
"""Adversarial security battery for the Keystone Seal receipt chain.

Every attack below produces a chain that MUST be rejected by kaf_verify.py
(nonzero exit, crashes count as rejection). The untouched chain is the
control and MUST pass. Attacks run against copies in a temp dir; the real
receipts are never touched.

Attack classes:
  A1  bit flips at spread offsets in each receipt file
  A2  semantic field tampering re-serialized canonically (attacker owns a
      correct JCS implementation)
  A3  signature transplant between receipts
  A4  key substitution: attacker re-signs a tampered receipt correctly with
      their own Ed25519 key (defeated only by the pinned key registry)
  A5  chain manipulation: drop the middle receipt; swap receipt order
  A6  canonicalization confusion: semantically identical JSON with different
      bytes (pretty-printed)
  A7  content-digest fixup: recompute Content-Digest over the tampered body
      while keeping the original signature
  A8  wrong genesis anchor
  A9  seal stripping: remove the signature field

Usage:
  python kaf/seal_security_test.py --receipts-dir kaf/receipts \
      --pub-file kaf/keys/kaf-seal.pub.json --genesis-anchor <MANIFEST>
"""
from __future__ import annotations

import argparse
import base64
import copy
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


def run_verify(receipts_dir: Path, pub_file: Path, genesis: Path | None) -> int:
    cmd = [sys.executable, str(VERIFY), "--receipts-dir", str(receipts_dir),
           "--pub-file", str(pub_file)]
    if genesis is not None:
        cmd += ["--genesis-anchor", str(genesis)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode


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

    src = args.receipts_dir
    pub = args.pub_file
    gen = args.genesis_anchor
    rcpts = sorted(src.glob("rcpt-*.json"))
    if len(rcpts) < 3:
        print("need a chain of at least 3 receipts to attack")
        return 2

    print("== control: untouched chain must verify ==")
    if run_verify(src, pub, gen) != 0:
        print("  FATAL: control chain does not verify; aborting")
        return 2
    print("  [OK] control verifies")

    print("== A1: bit flips ==")
    for r in rcpts:
        raw = bytearray(r.read_bytes())
        for off in (1, len(raw) // 3, len(raw) // 2, len(raw) - 2):
            c = fresh_copy(src)
            t = bytearray(raw)
            t[off] ^= 0x01
            (c / r.name).write_bytes(bytes(t))
            check(f"{r.name} flip@{off}", run_verify(c, pub, gen) != 0)

    print("== A2: canonical field tampering ==")
    for field, mut in [
        ("totals.all_green stays true, cells count lowered",
         lambda e: e["receipt"]["totals"].__setitem__("cells", 1)),
        ("first cell image_digest swapped",
         lambda e: e["receipt"]["cells"][0].__setitem__(
             "image_digest", "sha256:" + "0" * 64)),
        ("run id renamed",
         lambda e: e["receipt"]["run"].__setitem__("id", "forged-run")),
        ("prev link redirected",
         lambda e: e["receipt"]["prev"].__setitem__("sha256", "0" * 64)),
        ("corpus commit swapped",
         lambda e: e["receipt"]["corpus"].__setitem__("commit", "f" * 40)),
    ]:
        c = fresh_copy(src)
        rewrite_canonical(c / rcpts[1].name, mut)
        check(f"A2 {field}", run_verify(c, pub, gen) != 0)

    print("== A3: signature transplant ==")
    c = fresh_copy(src)
    a = json.loads((c / rcpts[0].name).read_bytes())
    b = json.loads((c / rcpts[1].name).read_bytes())
    b["seal"]["signature"] = a["seal"]["signature"]
    b["seal"]["signature_input"] = a["seal"]["signature_input"]
    b["seal"]["content_digest"] = a["seal"]["content_digest"]
    b["seal"]["created"] = a["seal"]["created"]
    (c / rcpts[1].name).write_bytes(canonicalize_bytes(b))
    check("A3 seal of receipt 1 transplanted onto receipt 2",
          run_verify(c, pub, gen) != 0)

    print("== A4: key substitution (attacker signs correctly) ==")
    try:
        from nacl.signing import SigningKey
        from algovoi_rfc9421_signer import sign_request
        c = fresh_copy(src)
        target = c / rcpts[1].name
        env = json.loads(target.read_bytes())
        env["receipt"]["run"]["purpose"] = "forged by attacker key"
        body = canonicalize_bytes(env["receipt"])
        atk = SigningKey(b"\x42" * 32)
        sig = sign_request(method=env["seal"]["method"],
                           authority=env["seal"]["authority"],
                           path=env["seal"]["path"], body=body,
                           private_key=(b"\x42" * 32).hex(),
                           keyid=env["seal"]["keyid"],
                           created=env["seal"]["created"])
        env["seal"]["signature"] = sig.signature
        env["seal"]["signature_input"] = sig.signature_input
        env["seal"]["content_digest"] = sig.content_digest
        env["seal"]["public_key_hex"] = atk.verify_key.encode().hex()
        target.write_bytes(canonicalize_bytes(env))
        check("A4 valid signature under attacker key + attacker pubkey in seal",
              run_verify(c, pub, gen) != 0)
    except ImportError:
        print("  (signer not installed here; A4 skipped, run where seal.py runs)")

    print("== A5: chain manipulation ==")
    c = fresh_copy(src)
    (c / rcpts[1].name).unlink()
    check("A5 middle receipt dropped", run_verify(c, pub, gen) != 0)
    c = fresh_copy(src)
    b0 = (c / rcpts[0].name).read_bytes()
    b1 = (c / rcpts[1].name).read_bytes()
    (c / rcpts[0].name).write_bytes(b1)
    (c / rcpts[1].name).write_bytes(b0)
    check("A5 receipt order swapped", run_verify(c, pub, gen) != 0)

    print("== A6: canonicalization confusion ==")
    c = fresh_copy(src)
    env = json.loads((c / rcpts[1].name).read_bytes())
    (c / rcpts[1].name).write_text(
        json.dumps(env, indent=2, sort_keys=False), encoding="utf-8")
    check("A6 semantically identical, non-canonical bytes",
          run_verify(c, pub, gen) != 0)

    print("== A7: content-digest fixup ==")
    c = fresh_copy(src)
    env = json.loads((c / rcpts[1].name).read_bytes())
    env["receipt"]["run"]["purpose"] = "tampered with digest fixup"
    body = canonicalize_bytes(env["receipt"])
    d = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
    env["seal"]["content_digest"] = f"sha-256=:{d}:"
    (c / rcpts[1].name).write_bytes(canonicalize_bytes(env))
    check("A7 recomputed Content-Digest, original signature",
          run_verify(c, pub, gen) != 0)

    print("== A8: wrong genesis anchor ==")
    wrong = Path(tempfile.mkdtemp(prefix="kafsec-")) / "wrong-manifest.txt"
    wrong.write_text("not the P0 manifest", encoding="utf-8")
    check("A8 chain verified against a different genesis anchor",
          run_verify(src, pub, wrong) != 0)

    print("== A9: seal stripping ==")
    c = fresh_copy(src)
    env = json.loads((c / rcpts[1].name).read_bytes())
    del env["seal"]["signature"]
    (c / rcpts[1].name).write_bytes(canonicalize_bytes(env))
    check("A9 signature field removed", run_verify(c, pub, gen) != 0)

    print("=" * 60)
    total = PASS + FAIL
    print(f"SEAL SECURITY BATTERY: {PASS}/{total} attacks rejected, "
          f"{FAIL} accepted")
    if FAIL == 0:
        print("RESULT: GREEN (every forgery class rejected; control verifies)")
        return 0
    print("RESULT: FAILURES PRESENT")
    return 1


if __name__ == "__main__":
    sys.exit(main())
