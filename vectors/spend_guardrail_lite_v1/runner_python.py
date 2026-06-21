"""
spend_guardrail_lite_v1 runner (Python).

Validates the 2 verdict vectors + 6 negatives + 2 invariants in
spend_guardrail_lite_v1.json using algovoi-substrate (>=0.4.0) on PyPI. The open,
content-addressed pre-payment decision:

    guardrail_ref = "sha256:" + SHA-256(JCS({agent_ref, mandate_ref, policy_bound_ref, verdict}))

verdict is a closed enumeration {ALLOW, DENY}; agent_ref / mandate_ref / policy_bound_ref
are pinned refs (a passport_ref, a mandate_ref, and a policy_bound_ref from
algovoi-policy-binding) imported by hash. An ALLOW bound under one policy snapshot does
not recompute under a rotated one; swapping the agent, the mandate, or the verdict diverges.

Usage:
    pip install algovoi-substrate>=0.4.0
    python runner_python.py [spend_guardrail_lite_v1.json]
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from algovoi_substrate import sha256_jcs

VERDICTS = ("ALLOW", "DENY")
_REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class _GuardError(ValueError):
    pass


def _prefixed(value) -> str:
    return "sha256:" + sha256_jcs(value)


def guardrail_ref(verdict, agent_ref, mandate_ref, policy_bound_ref) -> str:
    if verdict not in VERDICTS:
        raise _GuardError(f"verdict must be one of {VERDICTS}")
    for name, val in (("agent_ref", agent_ref), ("mandate_ref", mandate_ref),
                      ("policy_bound_ref", policy_bound_ref)):
        if not isinstance(val, str) or not _REF_RE.match(val):
            raise _GuardError(f"{name} must be a sha256: ref")
    return _prefixed({
        "agent_ref": agent_ref,
        "mandate_ref": mandate_ref,
        "policy_bound_ref": policy_bound_ref,
        "verdict": verdict,
    })


def main() -> int:
    here = Path(__file__).parent
    vf = Path(sys.argv[1]) if len(sys.argv) > 1 else here / "spend_guardrail_lite_v1.json"
    d = json.loads(vf.read_text(encoding="utf-8"))
    fails: list[str] = []

    for v in d["vectors"]:
        if guardrail_ref(v["verdict"], v["agent_ref"], v["mandate_ref"], v["policy_bound_ref"]) != v["expected_guardrail_ref"]:
            fails.append(v["id"])

    for n in d["negatives"]:
        if n["must"] == "reject":
            try:
                guardrail_ref(n["verdict"], n["agent_ref"], n["mandate_ref"], n["policy_bound_ref"])
                fails.append(f"{n['id']} (accepted, should reject)")
            except _GuardError:
                pass
        else:
            got = guardrail_ref(n["verdict"], n["agent_ref"], n["mandate_ref"], n["policy_bound_ref"])
            if got == n["claimed_guardrail_ref"]:
                fails.append(f"{n['id']} (tamper not detected)")
            elif "recomputes_to" in n and got != n["recomputes_to"]:
                fails.append(n["id"])

    v0 = d["vectors"][0]
    if len({guardrail_ref(w, v0["agent_ref"], v0["mandate_ref"], v0["policy_bound_ref"]) for w in VERDICTS}) != len(VERDICTS):
        fails.append("verdict-distinctness")
    try:
        guardrail_ref("BLOCK", v0["agent_ref"], v0["mandate_ref"], v0["policy_bound_ref"])
        fails.append("closed-enum (out-of-set accepted)")
    except _GuardError:
        pass

    total = len(d["vectors"]) + len(d["negatives"]) + 2
    if fails:
        print(f"FAIL ({len(fails)}/{total}): {', '.join(fails)}")
        return 1
    print(f"{total}/{total} PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
