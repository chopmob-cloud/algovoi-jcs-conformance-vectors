#!/usr/bin/env python3
"""
guard_keystone_v1 -- composition proof: the keystone record is admitted under the guard profile.

Proves offline from raw fields (RFC 8785 JCS + SHA-256, no package import):
  1. profile_ref recomputes from the profile, equals the published substrate_guard default.
  2. the keystone record's structural metrics recompute to the recorded values.
  3. every metric is within the profile's named bound (the guard ACCEPTS the record).
  4. the admitted record IS the keystone: every reference in it, and its ordered chain,
     recomputes from the keystone_v1 raw fields rather than being read from this trace.

This is a precondition / provenance binding, not a chain link: it shows the keystone was produced
over inputs the input-bounds gate admits.

Check 4 exists because the structural checks above cannot see reference values. Every
reference is 71 characters, so substituting one leaves byte_len, depth, nodes, max_string
and every other metric identical: the guard admitted the record's SHAPE, and the claim that
the shape belonged to the keystone was carried by this trace rather than verified. A record
with fabricated references was admitted exactly as readily as the real one.

Run:  pip install rfc8785 ; python verify_guard_keystone.py
      (runs from any working directory)
"""
from __future__ import annotations
import hashlib, json, sys
from pathlib import Path
import rfc8785

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent.parent / "vectors"
TRACE = HERE / "guard_keystone_trace.json"
SAFE_INT_MAX = 2**53 - 1
def _h(o): return hashlib.sha256(rfc8785.dumps(o)).hexdigest()

def metrics(v, depth=1):
    m = {"depth": depth, "nodes": 1, "max_array": 0, "max_string": 0, "max_keys": 0, "numbers_safe": True}
    def merge(c):
        m["depth"] = max(m["depth"], c["depth"]); m["nodes"] += c["nodes"]
        m["max_array"] = max(m["max_array"], c["max_array"]); m["max_string"] = max(m["max_string"], c["max_string"])
        m["max_keys"] = max(m["max_keys"], c["max_keys"]); m["numbers_safe"] = m["numbers_safe"] and c["numbers_safe"]
    if isinstance(v, bool): pass
    elif isinstance(v, dict):
        m["max_keys"] = len(v)
        for val in v.values(): merge(metrics(val, depth + 1))
    elif isinstance(v, list):
        m["max_array"] = len(v)
        for val in v: merge(metrics(val, depth + 1))
    elif isinstance(v, str): m["max_string"] = len(v)
    elif isinstance(v, int): m["numbers_safe"] = abs(v) <= SAFE_INT_MAX
    elif isinstance(v, float): m["numbers_safe"] = False
    return m

def main() -> int:
    t = json.loads(TRACE.read_text(encoding="utf-8"))
    P, rec, exp = t["profile"], t["keystone_record"], t["measured"]
    checks = []

    profile_ref = "sha256:" + _h(P)
    checks.append((profile_ref == t["expected_profile_ref"],
                   "profile_ref recomputes, equals the published substrate_guard default", profile_ref))

    byte_len = len(rfc8785.dumps(rec))
    m = metrics(rec)
    same = (byte_len == exp["byte_len"] and all(m[k] == exp[k] for k in ("depth","nodes","max_array","max_string","max_keys","numbers_safe")))
    checks.append((same, "keystone record metrics recompute to the recorded values", {"byte_len": byte_len, **m}))

    within = (byte_len <= P["max_bytes"] and m["depth"] <= P["max_depth"] and m["max_keys"] <= P["max_object_keys"]
              and m["max_array"] <= P["max_array_length"] and m["max_string"] <= P["max_string_length"]
              and m["nodes"] <= P["max_total_nodes"] and m["numbers_safe"])
    checks.append((within and t["verdict"] == "ACCEPT",
                   "every metric within the profile bounds -> guard ACCEPTS the keystone record", "ACCEPT"))

    # 4. the admitted record IS the keystone, derived rather than carried.
    def _ref(o): return "sha256:" + _h(o)
    ks = json.loads((HERE.parent / "keystone_v1" / "keystone_trace.json").read_text(encoding="utf-8"))
    st, kd = ks["steps"], ks["decision"]

    passport_ref = _ref(st["passport_ref"]["inputs"])
    mandate_ref = _ref(st["mandate_ref"]["inputs"])
    pol = st["policy_bound_ref"]
    policy_bound_ref = _ref({"policy_ref": _ref(pol["policy"]), "subject_ref": pol["subject_ref"]})
    decision_ref = _ref({"agent_ref": passport_ref, "mandate_ref": mandate_ref,
                         "policy_bound_ref": policy_bound_ref, "verdict": kd["verdict"]})
    ex = ks["execution"]
    execution_ref = _ref({"decision_ref": decision_ref, "action_type": ex["action_type"],
                          "scope": ex["scope"], "outcome": ex["outcome"],
                          "executed_at_ms": ex["executed_at_ms"]})
    chain = [passport_ref, mandate_ref, policy_bound_ref, decision_ref, execution_ref]
    trust_query_ref = _ref({"subject_refs": chain, "trust_outcome": ks["cap"]["trust_outcome"]})

    derived = {
        "passport_ref": passport_ref, "mandate_ref": mandate_ref,
        "policy_bound_ref": policy_bound_ref, "decision_ref": decision_ref,
        "execution_ref": execution_ref, "trust_query_ref": trust_query_ref,
    }
    bad = [k for k, v in derived.items() if rec.get(k) != v]
    if rec.get("chain") != chain:
        bad.append("chain")
    checks.append((not bad,
                   "the admitted record IS the keystone: all 6 references and the ordered chain "
                   "recompute from keystone_v1 raw fields",
                   "all derived" if not bad else f"mismatch: {bad}"))

    print("=" * 74)
    print("GUARD KEYSTONE -- composition proof (keystone admitted under the input-bounds profile)")
    print("=" * 74)
    npass = 0
    for i, (ok, desc, val) in enumerate(checks, 1):
        print(f"\n[{i}] {'PASS' if ok else 'FAIL'}  {desc}\n      value : {val}")
        npass += 1 if ok else 0
    print("\n" + "-" * 74)
    print(f"PASS {npass}/{len(checks)} -- the keystone record is admitted under the published guard profile.")
    return 0 if npass == len(checks) else 1

if __name__ == "__main__":
    sys.exit(main())
