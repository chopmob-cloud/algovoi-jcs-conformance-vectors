#!/usr/bin/env python3
"""Differential adversarial substrate -- Python canon probe (rfc8785).

Contract (identical across all 10 language probes):
  argv[1] = path to a cases file: {"cases":[{"id":..., "raw":"<raw json text>"}, ...]}
  For each case: parse case.raw with the NATIVE json parser, canonicalize the
  parsed value with THIS language's JCS library, SHA-256 the canonical bytes.
  Emit exactly one line per case to stdout:
      <id>\t h:<64-hex>     on success
      <id>\t R:<reason>     if native parse OR canonicalization refuses
  The probe carries no policy. Consensus (agree/reject/hazard) is decided by
  differential_driver.py comparing all 10 probes' verdicts. This is the property
  a 2-implementation corpus cannot express: N-way cross-language agreement.
"""
from __future__ import annotations
import hashlib, json, sys
import rfc8785

LANG = "python"


def verdict(raw: str) -> str:
    try:
        val = json.loads(raw)  # native parser, default settings
    except Exception as e:
        return "R:parse"
    try:
        canon = rfc8785.dumps(val)
    except Exception as e:
        return "R:canon"
    return "h:" + hashlib.sha256(canon).hexdigest()


def main(path: str) -> int:
    d = json.load(open(path, encoding="utf-8"))
    out = []
    for c in d["cases"]:
        out.append(f"{c['id']}\t{verdict(c['raw'])}")
    sys.stdout.write("\n".join(out) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
