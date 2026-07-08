#!/usr/bin/env python3
"""Corpus runner (python) for the keystone_decision_audit vector set.

Imports only the standard library plus a JCS library (rfc8785) -- no algovoi import. Recompute is the
test: it re-derives decision_audit_ref from inputs and checks every positive vector, every negative
(policy-rotation / passport / screen-omission divergence; malformed ref rejected), and the invariants.
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


def decision_audit_ref(decision_ref, passport_credential_ref, mandate_ref, policy_bound_ref,
                       screen_binding_ref=None) -> str:
    obj = {"decision_ref": decision_ref, "passport_credential_ref": passport_credential_ref,
           "mandate_ref": mandate_ref, "policy_bound_ref": policy_bound_ref}
    for name, val in list(obj.items()):
        if not isinstance(val, str) or not _REF_RE.match(val):
            raise ValueError(f"{name} must be a sha256: ref")
    if screen_binding_ref is not None:
        if not isinstance(screen_binding_ref, str) or not _REF_RE.match(screen_binding_ref):
            raise ValueError("screen_binding_ref must be a sha256: ref")
        obj["screen_binding_ref"] = screen_binding_ref
    return _prefixed(obj)


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    d = json.load(open(os.path.join(here, "keystone_decision_audit_v1.json"), encoding="utf-8"))
    fails = []

    for v in d["vectors"]:
        got = decision_audit_ref(v["decision_ref"], v["passport_credential_ref"], v["mandate_ref"],
                                 v["policy_bound_ref"], v.get("screen_binding_ref"))
        if got != v["expected_decision_audit_ref"]:
            fails.append(f"{v['id']}: {got} != {v['expected_decision_audit_ref']}")

    for n in d["negatives"]:
        if n["must"] == "reject":
            try:
                decision_audit_ref(n["decision_ref"], n["passport_credential_ref"], n["mandate_ref"],
                                   n["policy_bound_ref"], n.get("screen_binding_ref"))
                fails.append(f"{n['id']}: invalid input ACCEPTED (should reject)")
            except Exception:
                pass
        else:  # differ
            got = decision_audit_ref(n["decision_ref"], n["passport_credential_ref"], n["mandate_ref"],
                                     n["policy_bound_ref"], n.get("screen_binding_ref"))
            if got == n["claimed_decision_audit_ref"]:
                fails.append(f"{n['id']}: tamper NOT detected (recompute == claimed)")
            elif "recomputes_to" in n and got != n["recomputes_to"]:
                fails.append(f"{n['id']}: {got} != {n['recomputes_to']}")

    # invariant: screen presence is bound (screened != non-screened)
    v0 = d["vectors"][0]
    with_screen = decision_audit_ref(v0["decision_ref"], v0["passport_credential_ref"], v0["mandate_ref"],
                                     v0["policy_bound_ref"], v0["screen_binding_ref"])
    no_screen = decision_audit_ref(v0["decision_ref"], v0["passport_credential_ref"], v0["mandate_ref"],
                                   v0["policy_bound_ref"], None)
    if with_screen == no_screen:
        fails.append("screen-distinctness: screened and non-screened decision_audit_ref collided")
    # invariant: malformed ref rejected
    try:
        decision_audit_ref("not-a-ref", v0["passport_credential_ref"], v0["mandate_ref"], v0["policy_bound_ref"])
        fails.append("ref-form: malformed decision_ref was accepted")
    except Exception:
        pass

    total = len(d["vectors"]) + len(d["negatives"]) + 2
    if fails:
        print(f"FAIL ({len(fails)}/{total}):")
        for f in fails:
            print("  -", f)
        return 1
    print(f"PASS {total}/{total} -- keystone_decision_audit vectors reproduce byte-for-byte; decision "
          "bound to passport + mandate + policy + screen; policy-rotation, passport and screen-omission "
          "tamper detected; malformed ref rejected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
