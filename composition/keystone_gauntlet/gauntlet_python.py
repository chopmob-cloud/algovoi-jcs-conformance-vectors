#!/usr/bin/env python3
"""Keystone L3 fail-closed gauntlet -- Python impl (rfc8785).

Independent reimplementation of decision_audit_ref from the rules alone (no
algovoi import): "sha256:" + SHA-256(JCS({decision_ref, passport_credential_ref,
mandate_ref, policy_bound_ref, [screen_binding_ref]})), sha256: ref-form
enforced. Accepts every positive, fail-closes on every negative, holds both
invariants (screen presence bound; malformed ref rejected).

Usage: python gauntlet_python.py <keystone_decision_audit_v1.json>
"""
from __future__ import annotations
import hashlib, json, re, sys
import rfc8785

_REF = re.compile(r"^sha256:[0-9a-f]{64}$")


def decision_audit_ref(dr, pcr, mr, pbr, sbr=None) -> str:
    obj = {"decision_ref": dr, "passport_credential_ref": pcr,
           "mandate_ref": mr, "policy_bound_ref": pbr}
    for name, val in list(obj.items()):
        if not isinstance(val, str) or not _REF.match(val):
            raise ValueError(f"{name} must be a sha256: ref")
    if sbr is not None:
        if not isinstance(sbr, str) or not _REF.match(sbr):
            raise ValueError("screen_binding_ref must be a sha256: ref")
        obj["screen_binding_ref"] = sbr
    return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def main(path: str) -> int:
    d = json.load(open(path, encoding="utf-8"))
    ok = 0
    fails = []
    for v in d["vectors"]:
        got = decision_audit_ref(v["decision_ref"], v["passport_credential_ref"],
                                 v["mandate_ref"], v["policy_bound_ref"], v.get("screen_binding_ref"))
        if got == v["expected_decision_audit_ref"]:
            ok += 1
        else:
            fails.append(f"{v['id']}: accept-mismatch")
    for n in d["negatives"]:
        if n["must"] == "reject":
            try:
                decision_audit_ref(n["decision_ref"], n["passport_credential_ref"],
                                   n["mandate_ref"], n["policy_bound_ref"], n.get("screen_binding_ref"))
                fails.append(f"{n['id']}: invalid ACCEPTED")
            except Exception:
                ok += 1
        else:
            got = decision_audit_ref(n["decision_ref"], n["passport_credential_ref"],
                                     n["mandate_ref"], n["policy_bound_ref"], n.get("screen_binding_ref"))
            if got != n["claimed_decision_audit_ref"]:
                ok += 1
            else:
                fails.append(f"{n['id']}: tamper NOT detected")
    v0 = d["vectors"][0]
    a = decision_audit_ref(v0["decision_ref"], v0["passport_credential_ref"], v0["mandate_ref"],
                           v0["policy_bound_ref"], v0["screen_binding_ref"])
    b = decision_audit_ref(v0["decision_ref"], v0["passport_credential_ref"], v0["mandate_ref"],
                           v0["policy_bound_ref"], None)
    ok += 1 if a != b else fails.append("screen-distinctness collision") or 0
    try:
        decision_audit_ref("bad", v0["passport_credential_ref"], v0["mandate_ref"], v0["policy_bound_ref"])
        fails.append("malformed-ref accepted")
    except Exception:
        ok += 1
    total = len(d["vectors"]) + len(d["negatives"]) + 2
    for f in fails:
        print("  FAIL", f)
    print(f"KEYSTONE-GAUNTLET python {ok}/{total}")
    return 0 if ok == total and not fails else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
