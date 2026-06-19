#!/usr/bin/env python3
"""Adversarial gauntlet runner -- Python (independent reimplementation, no algovoi import).

Reimplements the three substrate-1 rejection checks (transition_preimage, action_ref,
audit_chain) from the rules alone, then runs them against adversarial_isolation_v1.
Emits one line per vector and a final 'GAUNTLET python <ok>/<total>'. The point is
cross-implementation FAIL-CLOSED parity: every language must accept the control and
reject all 11 mutations identically.

Usage: python gauntlet_python.py /path/to/adversarial_isolation_v1.json
"""
import hashlib
import json
import sys

_HEX = set("0123456789abcdef")


def is_hex64(s):
    return isinstance(s, str) and len(s) == 64 and all(c in _HEX for c in s)


def is_uint(x):
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


def nonempty_str(x):
    return isinstance(x, str) and len(x) > 0


def jcs_compact(o):
    # canonical sorted-key compact JSON; byte-identical to RFC 8785 JCS for the
    # ASCII-string / integer payloads in this vector set.
    return json.dumps(o, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def check_transition_preimage(o):
    if not isinstance(o, dict):
        return False
    if not is_hex64(o.get("action_ref")):
        return False
    if not nonempty_str(o.get("state")):
        return False
    for k in ("transition_timestamp_ms", "authority_verified_at_ms", "revocation_check_at_ms"):
        if not is_uint(o.get(k)):
            return False
    return True


def check_action_ref(o):
    if not isinstance(o, dict):
        return False
    for k in ("agent_id", "action_type", "scope"):
        if not nonempty_str(o.get(k)):
            return False
    return is_uint(o.get("timestamp_ms"))


def check_audit_chain(rows):
    if not isinstance(rows, list) or not rows:
        return False
    prev = None
    for i, r in enumerate(rows):
        if not isinstance(r, dict):
            return False
        if r.get("chain_position") != i:
            return False
        if i == 0:
            if r.get("prev_hash") is not None:
                return False
        elif r.get("prev_hash") != prev:
            return False
        recomputed = hashlib.sha256(jcs_compact(r.get("payload")).encode("utf-8")).hexdigest()
        if recomputed != r.get("content_hash"):
            return False
        prev = r.get("content_hash")
    return True


CHECKS = {
    "transition_preimage": check_transition_preimage,
    "action_ref": check_action_ref,
    "audit_chain": check_audit_chain,
}


def main():
    data = json.load(open(sys.argv[1], encoding="utf-8"))
    ok = 0
    total = 0
    for v in data["vectors"]:
        total += 1
        verdict = "accept" if CHECKS[v["check"]](v["input"]) else "reject"
        expected = "reject" if v["expectation"] == "reject" else "accept"
        good = verdict == expected
        ok += good
        print(f'{v["vector_id"]} {verdict} expect={expected} {"OK" if good else "MISMATCH"}')
    print(f"GAUNTLET python {ok}/{total}")
    sys.exit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
