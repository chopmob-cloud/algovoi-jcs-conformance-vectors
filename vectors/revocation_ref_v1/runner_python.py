#!/usr/bin/env python3
"""Corpus runner (python) for revocation_ref_v1 -- no algovoi import.

Reimplements revocation_ref + verify_revocation_chain from the rule alone.
Fail-closed: every malformed revocation is rejected; every tampered/reordered
chain fails to verify. Exit 0 only when all verdicts hold.

    pip install rfc8785 ; python runner_python.py revocation_ref_v1.json
"""
from __future__ import annotations
import hashlib, json, os, re, sys
import rfc8785

REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REASONS = ("USER_REQUESTED", "COMPLIANCE_TRIGGERED", "EXPIRED", "KEY_COMPROMISE", "SUPERSEDED", "ADMIN")
STATUS = ("active", "suspended", "revoked", "inactive")


def _ref(name, v):
    if not isinstance(v, str) or not REF_RE.match(v):
        raise ValueError(name)
    return v


def _int(name, v):
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        raise ValueError(name)
    return v


def _enum(name, v, allowed):
    if v not in allowed:
        raise ValueError(name)
    return v


def _str(name, v):
    if not isinstance(v, str) or v == "":
        raise ValueError(name)
    return v


def revocation_ref(f) -> str:
    prev = f.get("prev_revocation_ref")
    obj = {
        "canon_version": "jcs-rfc8785-v1", "type": "revocation_link",
        "subject_ref": _ref("subject_ref", f["subject_ref"]),
        "revoked_at_ms": _int("revoked_at_ms", f["revoked_at_ms"]),
        "reason_code": _enum("reason_code", f["reason_code"], REASONS),
        "issuer_did": _str("issuer_did", f["issuer_did"]),
        "prev_status": _enum("prev_status", f["prev_status"], STATUS),
        "new_status": _enum("new_status", f["new_status"], STATUS),
        "seq": _int("seq", f["seq"]),
        "prev_revocation_ref": None if prev is None else _ref("prev_revocation_ref", prev),
    }
    return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def verify_chain(links) -> bool:
    prev = None
    for i, link in enumerate(links):
        if link.get("seq") != i:
            return False
        if link.get("prev_revocation_ref") != prev:
            return False
        prev = "sha256:" + hashlib.sha256(rfc8785.dumps(link)).hexdigest()
    return True


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "revocation_ref_v1.json")
    d = json.load(open(path, encoding="utf-8"))
    ok, fails = 0, []
    for v in d["vectors"]:
        try:
            ok += 1 if revocation_ref(v) == v["expected_revocation_ref"] else fails.append(f"{v['id']}: mismatch") or 0
        except Exception:
            fails.append(f"{v['id']}: valid REJECTED")
    for n in d["negatives"]:
        try:
            revocation_ref(n); fails.append(f"{n['id']}: malformed ACCEPTED")
        except Exception:
            ok += 1
    for t in d["tamper"]:
        ok += 1 if revocation_ref(t) != t["claimed_revocation_ref"] else fails.append(f"{t['id']}: tamper NOT detected") or 0
    for c in d["chain_valid"]:
        ok += 1 if verify_chain(c["links"]) else fails.append(f"{c['id']}: valid chain REJECTED") or 0
    for c in d["chain_invalid"]:
        ok += 1 if not verify_chain(c["links"]) else fails.append(f"{c['id']}: bad chain ACCEPTED") or 0
    total = len(d["vectors"]) + len(d["negatives"]) + len(d["tamper"]) + len(d["chain_valid"]) + len(d["chain_invalid"])
    for f in fails:
        print("  FAIL", f)
    if fails:
        print(f"FAIL ({len(fails)}/{total})")
        return 1
    if total == 0:
        print("FAIL: zero items (positive-work floor -- an empty file must not pass)")
        return 1
    print(f"PASS {ok}/{total} -- revocation links reproduce; malformed rejected fail-closed; tamper detected; chain integrity holds.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
