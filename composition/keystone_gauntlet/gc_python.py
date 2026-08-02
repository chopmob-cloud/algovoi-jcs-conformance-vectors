#!/usr/bin/env python3
"""Keystone L3 gauntlet -- guard_context, Python impl (rfc8785).
Independent reimplementation of guard_context_ref (no algovoi import).
Usage: python gc_python.py <keystone_guard_context_v1.json>"""
from __future__ import annotations
import hashlib, json, re, sys
import rfc8785

_REF = re.compile(r"^sha256:[0-9a-f]{64}$")


def guard_context_ref(ts, policy_ref, mandate_ref, passport_credential_ref) -> str:
    if isinstance(ts, bool) or not isinstance(ts, int) or ts < 0:
        raise ValueError("guard_timestamp_ms must be a non-negative integer")
    for name, val in (("policy_ref", policy_ref), ("mandate_ref", mandate_ref),
                      ("passport_credential_ref", passport_credential_ref)):
        if not isinstance(val, str) or not _REF.match(val):
            raise ValueError(f"{name} must be a sha256: ref")
    obj = {"canon_version": "jcs-rfc8785-v1", "type": "guard_context",
           "guard_timestamp_ms": ts, "policy_ref": policy_ref,
           "mandate_ref": mandate_ref, "passport_credential_ref": passport_credential_ref}
    return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def main(path: str) -> int:
    d = json.load(open(path, encoding="utf-8"))
    ok, fails = 0, []
    for v in d["vectors"]:
        got = guard_context_ref(v["guard_timestamp_ms"], v["policy_ref"], v["mandate_ref"], v["passport_credential_ref"])
        ok += 1 if got == v["expected_guard_context_ref"] else fails.append(f"{v['id']}: accept-mismatch") or 0
    for n in d["negatives"]:
        if n["must"] == "reject":
            try:
                guard_context_ref(n["guard_timestamp_ms"], n["policy_ref"], n["mandate_ref"], n["passport_credential_ref"])
                fails.append(f"{n['id']}: invalid ACCEPTED")
            except Exception:
                ok += 1
        else:
            got = guard_context_ref(n["guard_timestamp_ms"], n["policy_ref"], n["mandate_ref"], n["passport_credential_ref"])
            ok += 1 if got != n["claimed_guard_context_ref"] else fails.append(f"{n['id']}: tamper NOT detected") or 0
    v0 = d["vectors"][0]
    a = guard_context_ref(v0["guard_timestamp_ms"], v0["policy_ref"], v0["mandate_ref"], v0["passport_credential_ref"])
    b = guard_context_ref(v0["guard_timestamp_ms"] + 1, v0["policy_ref"], v0["mandate_ref"], v0["passport_credential_ref"])
    ok += 1 if a != b else fails.append("moment-distinctness collision") or 0
    try:
        guard_context_ref(1720000000000.5, v0["policy_ref"], v0["mandate_ref"], v0["passport_credential_ref"])
        fails.append("float-ts accepted")
    except Exception:
        ok += 1
    total = len(d["vectors"]) + len(d["negatives"]) + 2
    for f in fails:
        print("  FAIL", f)
    print(f"KEYSTONE-GAUNTLET-GC python {ok}/{total}")
    return 0 if ok == total and not fails else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
