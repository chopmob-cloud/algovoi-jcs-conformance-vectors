#!/usr/bin/env python3
"""Independent verifier for the delegation_ref vector set.

Imports only the standard library plus a JCS library (rfc8785) -- no algovoi
package import. Recompute is the test: it re-derives delegation_ref from each
envelope and checks every positive (byte-identical, including the reordered-key
case and the chain link), every negative (a tampered field diverges; a malformed
validity bound is rejected), and the invariants (key-order, chain integrity)
against vectors.json. Exit 0 only when all verdicts hold.

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


def delegation_ref(envelope) -> str:
    """Recompute delegation_ref = "sha256:" + hex(SHA-256(JCS({6 fields}))) with validation."""
    obj = {}
    for name in ("delegator_id", "delegate_id", "scope"):
        val = envelope.get(name)
        if not isinstance(val, str) or not val:
            raise ValueError(f"{name} must be a non-empty string")
        obj[name] = val
    for name in ("not_before_ms", "not_after_ms"):
        val = envelope.get(name)
        if isinstance(val, bool) or not isinstance(val, int) or val < 0:
            raise ValueError(f"{name} must be a non-negative integer (integer-millisecond)")
        obj[name] = val
    if obj["not_after_ms"] <= obj["not_before_ms"]:
        raise ValueError("not_after_ms must be greater than not_before_ms")
    prev = envelope.get("prev_delegation_ref", "")
    if prev != "" and not _REF_RE.match(prev):
        raise ValueError('prev_delegation_ref must be "" or a "sha256:" 64-hex ref')
    obj["prev_delegation_ref"] = prev
    payload = {k: obj[k] for k in ("delegate_id", "delegator_id", "not_after_ms",
                                   "not_before_ms", "prev_delegation_ref", "scope")}
    return "sha256:" + hashlib.sha256(rfc8785.dumps(payload)).hexdigest()


def verify_chain(envelopes):
    refs, prev = [], ""
    for i, env in enumerate(envelopes):
        if env.get("prev_delegation_ref", "") != prev:
            raise ValueError(f"chain break at link {i}")
        ref = delegation_ref(env)
        refs.append(ref)
        prev = ref
    return refs


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    vf = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "delegation_ref_v1.json")
    d = json.load(open(vf, encoding="utf-8"))
    fails = []

    for v in d["positives"]:
        try:
            got = delegation_ref(v["envelope"])
        except Exception as exc:
            fails.append(f"{v['id']}: unexpected reject ({exc})")
            continue
        if got != v["expected_delegation_ref"]:
            fails.append(f"{v['id']}: {got} != {v['expected_delegation_ref']}")

    for n in d["negatives"]:
        claimed = n["claimed_delegation_ref"]
        if n["must"] == "reject":
            try:
                delegation_ref(n["envelope"])
                fails.append(f"{n['id']}: malformed envelope ACCEPTED (should reject)")
            except Exception:
                pass
        else:
            try:
                got = delegation_ref(n["envelope"])
            except Exception as exc:
                fails.append(f"{n['id']}: unexpected reject ({exc})")
                continue
            if got == claimed:
                fails.append(f"{n['id']}: tamper NOT detected (recompute == claimed)")
            elif "recomputes_to" in n and got != n["recomputes_to"]:
                fails.append(f"{n['id']}: {got} != {n['recomputes_to']}")

    # invariant: key-order
    root = d["root_envelope"]
    reordered = {k: root[k] for k in reversed(list(root))}
    if delegation_ref(root) != delegation_ref(reordered):
        fails.append("key-order-invariance: delegation_ref(root) != delegation_ref(reordered)")

    # invariant: chain integrity
    try:
        chain = verify_chain([d["root_envelope"], d["chain_envelope"]])
        if chain != [d["root_delegation_ref"], d["chain_delegation_ref"]]:
            fails.append("chain-integrity: verify_chain produced unexpected refs")
    except Exception as exc:
        fails.append(f"chain-integrity: verify_chain raised ({exc})")

    total = len(d["positives"]) + len(d["negatives"]) + 2
    if fails:
        print(f"FAIL ({len(fails)}/{total}):")
        for f in fails:
            print("  -", f)
        return 1
    print(f"PASS {total}/{total} -- delegation_ref vectors reproduce byte-for-byte; tamper "
          "detected (scope / expiry / delegate / chain-link); malformed validity bound "
          "rejected; key-order invariant; chain integrity holds.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
