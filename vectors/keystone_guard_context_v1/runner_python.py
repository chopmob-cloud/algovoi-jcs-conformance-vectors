#!/usr/bin/env python3
"""Corpus runner (python) for the keystone_guard_context vector set.

Imports only the standard library plus a JCS library (rfc8785) -- no algovoi import. Recompute is the
test: it re-derives guard_context_ref from inputs and checks the positive vector, every negative
(timestamp / passport divergence; float timestamp and malformed ref rejected), and the invariants.
Exit 0 only when all verdicts hold.

Run:  pip install rfc8785 ; python verify.py
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys

import rfc8785

_REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _prefixed(value) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def guard_context_ref(guard_timestamp_ms, policy_ref, mandate_ref, passport_credential_ref) -> str:
    if isinstance(guard_timestamp_ms, bool) or not isinstance(guard_timestamp_ms, int) or guard_timestamp_ms < 0:
        raise ValueError("guard_timestamp_ms must be a non-negative integer millisecond")
    for name, val in (("policy_ref", policy_ref), ("mandate_ref", mandate_ref),
                      ("passport_credential_ref", passport_credential_ref)):
        if not isinstance(val, str) or not _REF_RE.match(val):
            raise ValueError(f"{name} must be a sha256: ref")
    return _prefixed({"canon_version": "jcs-rfc8785-v1", "type": "guard_context",
                      "guard_timestamp_ms": guard_timestamp_ms, "policy_ref": policy_ref,
                      "mandate_ref": mandate_ref, "passport_credential_ref": passport_credential_ref})


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    d = json.load(open(os.path.join(here, "keystone_guard_context_v1.json"), encoding="utf-8"))
    fails = []

    for v in d["vectors"]:
        got = guard_context_ref(v["guard_timestamp_ms"], v["policy_ref"], v["mandate_ref"],
                                v["passport_credential_ref"])
        if got != v["expected_guard_context_ref"]:
            fails.append(f"{v['id']}: {got} != {v['expected_guard_context_ref']}")

    for n in d["negatives"]:
        if n["must"] == "reject":
            try:
                guard_context_ref(n["guard_timestamp_ms"], n["policy_ref"], n["mandate_ref"],
                                  n["passport_credential_ref"])
                fails.append(f"{n['id']}: invalid input ACCEPTED (should reject)")
            except Exception:
                pass
        else:  # differ
            got = guard_context_ref(n["guard_timestamp_ms"], n["policy_ref"], n["mandate_ref"],
                                    n["passport_credential_ref"])
            if got == n["claimed_guard_context_ref"]:
                fails.append(f"{n['id']}: tamper NOT detected (recompute == claimed)")
            elif "recomputes_to" in n and got != n["recomputes_to"]:
                fails.append(f"{n['id']}: {got} != {n['recomputes_to']}")

    # invariant: moment distinctness (timestamp shift diverges)
    v0 = d["vectors"][0]
    r_t0 = guard_context_ref(v0["guard_timestamp_ms"], v0["policy_ref"], v0["mandate_ref"], v0["passport_credential_ref"])
    r_t1 = guard_context_ref(v0["guard_timestamp_ms"] + 1, v0["policy_ref"], v0["mandate_ref"], v0["passport_credential_ref"])
    if r_t0 == r_t1:
        fails.append("moment-distinctness: guard_context_ref did not change when the timestamp changed")
    # invariant: integer-ms rule (float rejected)
    try:
        guard_context_ref(1720000000000.5, v0["policy_ref"], v0["mandate_ref"], v0["passport_credential_ref"])
        fails.append("integer-ms-rule: a floating-point guard_timestamp_ms was accepted")
    except Exception:
        pass

    total = len(d["vectors"]) + len(d["negatives"]) + 2
    if fails:
        print(f"FAIL ({len(fails)}/{total}):")
        for f in fails:
            print("  -", f)
        return 1
    print(f"PASS {total}/{total} -- keystone_guard_context vectors reproduce byte-for-byte; context bound "
          "to moment + policy + mandate + passport; timestamp and passport tamper detected; float "
          "timestamp and malformed ref rejected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
