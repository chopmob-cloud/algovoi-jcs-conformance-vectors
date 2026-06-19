"""
policy_binding_v1 runner (Python).

Validates the 3 policy_ref + 6 policy_bound_ref vectors + 3 rotation negatives + 2
invariants in policy_binding_v1.json using algovoi-substrate (>=0.4.0) on PyPI.
Additive policy-snapshot binding over a frozen subject ref:

    policy_ref       = "sha256:" + SHA-256(JCS(policy_document))
    policy_bound_ref = "sha256:" + SHA-256(JCS({policy_ref, subject_ref}))

subject_ref is imported by hash (a settlement-action binding_ref, or a retention_chain
ref v0/v1). A record sealed under policy P fails recomputation under a rotated P'.

Usage:
    pip install algovoi-substrate>=0.4.0
    python runner_python.py [policy_binding_v1.json]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from algovoi_substrate import sha256_jcs


def _prefixed(value) -> str:
    return "sha256:" + sha256_jcs(value)


def policy_ref(policy_document) -> str:
    return _prefixed(policy_document)


def policy_bound_ref(subject_ref, pref) -> str:
    return _prefixed({"policy_ref": pref, "subject_ref": subject_ref})


def main() -> int:
    here = Path(__file__).parent
    vf = Path(sys.argv[1]) if len(sys.argv) > 1 else here / "policy_binding_v1.json"
    d = json.loads(vf.read_text(encoding="utf-8"))
    policies = d["policies"]
    fails: list[str] = []

    for name, exp in d["expected_policy_ref"].items():
        if policy_ref(policies[name]) != exp:
            fails.append(f"policy_ref[{name}]")

    for v in d["vectors"]:
        got = policy_bound_ref(v["subject_ref"], policy_ref(policies[v["policy"]]))
        if got != v["expected_policy_bound_ref"]:
            fails.append(v["id"])

    for n in d["negative_rotation"]:
        sealed = policy_bound_ref(n["subject_ref"], policy_ref(policies[n["sealed_under"]]))
        reverif = policy_bound_ref(n["subject_ref"], policy_ref(policies[n["verified_under"]]))
        if sealed == reverif:
            fails.append(f"{n['id']} (rotation not detected)")

    if policy_ref(policies["P"]) != policy_ref(policies["P_shuffled"]):
        fails.append("key-order-invariance")
    p = policy_ref(policies["P"])
    bound = [policy_bound_ref(r, p) for r in d["subjects"].values()]
    if len(set(bound)) != len(bound):
        fails.append("subject-binding (collision across subjects)")

    total = len(d["expected_policy_ref"]) + len(d["vectors"]) + len(d["negative_rotation"]) + 2
    if fails:
        print(f"FAIL ({len(fails)}/{total}): {', '.join(fails)}")
        return 1
    print(f"{total}/{total} PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
