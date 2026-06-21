"""
substrate_guard_v1 runner (Python) — independent reference impl.

Validates the deterministic input-bounds gate:

    profile_ref = "sha256:" + SHA-256(JCS(profile))
    guard(value, profile) -> accept, or reject with a named code, BEFORE canonicalization

This runner reimplements the gate from scratch against the published canonicalizer
(`algovoi-substrate` >= 0.4.0): the conformance claim is that an INDEPENDENT implementation enforces the
same bounds and rejects the same hostile inputs with the same code, and computes the same profile_ref.

    pip install algovoi-substrate>=0.4.0
    python runner_python.py [substrate_guard_v1.json]
"""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path

from algovoi_substrate import canonicalize_bytes, sha256_jcs

_SAFE_INT = 2 ** 53 - 1


class GuardError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def profile_ref(profile: dict) -> str:
    return "sha256:" + sha256_jcs(profile)


def guard(value, p: dict) -> bool:
    nodes = 0

    def walk(v, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > p["max_total_nodes"]:
            raise GuardError("REJECT_OVER_NODES")
        if depth > p["max_depth"]:
            raise GuardError("REJECT_OVER_DEPTH")
        if v is None or isinstance(v, bool):
            return
        if isinstance(v, int):
            if p["number_safety"] and abs(v) > _SAFE_INT:
                raise GuardError("REJECT_UNSAFE_NUMBER")
        elif isinstance(v, float):
            if p["number_safety"] and not math.isfinite(v):
                raise GuardError("REJECT_UNSAFE_NUMBER")
        elif isinstance(v, str):
            if len(v) > p["max_string_length"]:
                raise GuardError("REJECT_OVER_STRING")
        elif isinstance(v, dict):
            if len(v) > p["max_object_keys"]:
                raise GuardError("REJECT_TOO_MANY_KEYS")
            for k, val in v.items():
                if not isinstance(k, str) or len(k) > p["max_string_length"]:
                    raise GuardError("REJECT_OVER_STRING")
                walk(val, depth + 1)
        elif isinstance(v, list):
            if len(v) > p["max_array_length"]:
                raise GuardError("REJECT_OVER_ARRAY")
            for item in v:
                walk(item, depth + 1)
        else:
            raise GuardError("REJECT_UNSAFE_NUMBER")

    walk(value, 1)
    if len(canonicalize_bytes(value)) > p["max_bytes"]:
        raise GuardError("REJECT_OVER_SIZE")
    return True


def main() -> int:
    here = Path(__file__).parent
    vf = Path(sys.argv[1]) if len(sys.argv) > 1 else here / "substrate_guard_v1.json"
    d = json.loads(vf.read_text(encoding="utf-8"))
    fails: list[str] = []

    # profile_ref construction
    if profile_ref(d["default_profile"]) != d["expected_default_profile_ref"]:
        fails.append("default_profile_ref")
    for v in d["profile_ref_vectors"]:
        if profile_ref(v["profile"]) != v["expected_profile_ref"]:
            fails.append(v["id"])

    # control values MUST accept
    for a in d["accept"]:
        try:
            guard(a["value"], a["profile"])
        except GuardError as e:
            fails.append(f"{a['id']} (rejected {e.code}, should accept)")

    # each reject vector MUST reject with the named code
    for r in d["reject"]:
        try:
            guard(r["value"], r["profile"])
            fails.append(f"{r['id']} (accepted, should reject {r['expected_code']})")
        except GuardError as e:
            if e.code != r["expected_code"]:
                fails.append(f"{r['id']} (got {e.code}, want {r['expected_code']})")

    # key-order invariance on the profile
    snap = d["default_profile"]
    reordered = {k: snap[k] for k in reversed(list(snap))}
    if profile_ref(reordered) != d["expected_default_profile_ref"]:
        fails.append("inv-key-order")

    total = 1 + len(d["profile_ref_vectors"]) + len(d["accept"]) + len(d["reject"]) + 1
    if fails:
        print(f"FAIL ({len(fails)}/{total}): {', '.join(fails)}")
        return 1
    print(f"{total}/{total} PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
