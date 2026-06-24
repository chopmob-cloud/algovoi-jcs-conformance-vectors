#!/usr/bin/env python3
"""
guard_keystone_v1 composition generator.

Provenance binding (a precondition, not a chain link): the keystone record is admitted under the
published substrate-guard input-bounds profile. Proves the profile_ref recomputes to the published
value, and the keystone record is within every named bound of that profile (so the deterministic
input gate that runs before canonicalisation ACCEPTS it).

  profile_ref = "sha256:" + SHA-256(JCS(profile))

No new hashing primitive: reuses the substrate_guard_v1 default profile (published profile_ref) and
the keystone record. The bound checks are pure structural metrics, identical across implementations.

Usage:  pip install rfc8785 ; python generate_guard_keystone.py
"""
from __future__ import annotations
import hashlib, json, sys
from pathlib import Path
import rfc8785

OUT = Path(__file__).parent / "guard_keystone_trace.json"
SAFE_INT_MAX = 2**53 - 1

PROFILE = {"name": "guard-receipt-v1", "max_bytes": 65536, "max_depth": 32, "max_object_keys": 256,
           "max_array_length": 1024, "max_string_length": 8192, "max_total_nodes": 4096, "number_safety": True}
EXPECT_PROFILE_REF = "sha256:a4791b13c67a16109b85ef67fc65700ea902b6ad40dad44d8556632c3d5524a6"

PASSPORT = "sha256:b3594e33998af01bd1ad208172c5c1ac586daa8c75781379f034d97e50b1a9be"
MANDATE  = "sha256:a4f8cb5ee09b29478ac1cc2f468d66e16d3d25f7a229a31d22ad521e11d04d35"
POLICY   = "sha256:aaee2091799f376ee8cac802ea4920feaa4eca52950488a3e047ff82e6959a21"
DECISION = "sha256:2a444c629892f44fde1bd004aba9be01dd6cc7fe251eecdd545b82dca9f0bf97"
EXECUTION= "sha256:f6e2bfc15b085ed51c4c972de81d1c6b00f4e55b272e2aa12e56bb7c521fc65a"
TRUST    = "sha256:18fb601a08c71eb6bed11e1c117f33bdc0ada6d635ea9bb9cca15e8410ce7ebd"

KEYSTONE_RECORD = {
    "canon_version": "jcs-rfc8785-v1", "type": "execution_keystone",
    "passport_ref": PASSPORT, "mandate_ref": MANDATE, "policy_bound_ref": POLICY, "verdict": "ALLOW",
    "decision_ref": DECISION, "action_type": "payment", "scope": "bilateral", "outcome": "COMMITTED",
    "executed_at_ms": 1716460800000, "execution_ref": EXECUTION, "trust_outcome": "TRUSTED",
    "trust_query_ref": TRUST, "chain": [PASSPORT, MANDATE, POLICY, DECISION, EXECUTION],
}

def _h(o): return hashlib.sha256(rfc8785.dumps(o)).hexdigest()

def metrics(v, depth=1):
    m = {"depth": depth, "nodes": 1, "max_array": 0, "max_string": 0, "max_keys": 0, "numbers_safe": True}
    def merge(c):
        m["depth"] = max(m["depth"], c["depth"]); m["nodes"] += c["nodes"]
        m["max_array"] = max(m["max_array"], c["max_array"]); m["max_string"] = max(m["max_string"], c["max_string"])
        m["max_keys"] = max(m["max_keys"], c["max_keys"]); m["numbers_safe"] = m["numbers_safe"] and c["numbers_safe"]
    if isinstance(v, bool):
        pass
    elif isinstance(v, dict):
        m["max_keys"] = len(v)
        for val in v.values(): merge(metrics(val, depth + 1))
    elif isinstance(v, list):
        m["max_array"] = len(v)
        for val in v: merge(metrics(val, depth + 1))
    elif isinstance(v, str):
        m["max_string"] = len(v)
    elif isinstance(v, int):
        m["numbers_safe"] = abs(v) <= SAFE_INT_MAX
    elif isinstance(v, float):
        m["numbers_safe"] = False
    return m

def main() -> int:
    profile_ref = "sha256:" + _h(PROFILE)
    assert profile_ref == EXPECT_PROFILE_REF, profile_ref
    byte_len = len(rfc8785.dumps(KEYSTONE_RECORD))
    m = metrics(KEYSTONE_RECORD)
    within = (byte_len <= PROFILE["max_bytes"] and m["depth"] <= PROFILE["max_depth"]
              and m["max_keys"] <= PROFILE["max_object_keys"] and m["max_array"] <= PROFILE["max_array_length"]
              and m["max_string"] <= PROFILE["max_string_length"] and m["nodes"] <= PROFILE["max_total_nodes"]
              and m["numbers_safe"])
    assert within, (byte_len, m)

    trace = {
        "set": "guard_keystone_v1",
        "title": "The keystone record is admitted under the substrate-guard profile",
        "canon_version": "jcs-rfc8785-v1",
        "summary": (
            "Provenance / precondition binding (not a chain link): the input-bounds profile_ref "
            "recomputes to the published value, and the keystone record is within every named bound "
            "of that profile, so the deterministic guard that runs before canonicalisation ACCEPTS it."
        ),
        "profile": PROFILE,
        "expected_profile_ref": profile_ref,
        "keystone_record": KEYSTONE_RECORD,
        "measured": {"byte_len": byte_len, **m},
        "verdict": "ACCEPT",
    }
    OUT.write_text(json.dumps(trace, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("wrote", OUT.name)
    print("  profile_ref:", profile_ref)
    print("  measured   :", {"byte_len": byte_len, **m})
    print("  verdict    : ACCEPT (within all profile bounds)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
