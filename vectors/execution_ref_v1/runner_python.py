"""
execution_ref_v1 runner (Python).

Validates the decision-bound execution-evidence primitive:

    execution_ref = "sha256:" + SHA-256(JCS({decision_ref, action_type, scope,
                                            outcome, executed_at_ms}))

Checks: (1) positive construction; (2) closed outcome enum; (3) each negative
recomputes to a DIFFERENT ref (every field load-bearing); (4) an RFC 3339 string
timestamp is REJECTED, not converted then hashed (Substrate Rule 2); (5) cross-set
composition: the decision_ref inputs are byte-identical to spend_decision_v1
expected_decision_ref (the keystone composes decision -> execution).

    pip install algovoi-execution-ref      # any substrate version
    # or, once published:  pip install algovoi-substrate>=1.0.0   (native)
    python runner_python.py [execution_ref_v1.json]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# execution_ref ships natively in substrate 1.0.0+; until then (and on any
# substrate version) the standalone algovoi-execution-ref app provides it.
try:
    from algovoi_substrate import execution_ref
    from algovoi_substrate.execution_ref import ExecutionRefError
except ImportError:
    from algovoi_execution_ref import execution_ref, ExecutionRefError


def _ref(v) -> str:
    return execution_ref(
        decision_ref=v["decision_ref"], action_type=v["action_type"],
        scope=v["scope"], outcome=v["outcome"], executed_at_ms=v["executed_at_ms"],
    )


def main() -> int:
    here = Path(__file__).parent
    vf = Path(sys.argv[1]) if len(sys.argv) > 1 else here / "execution_ref_v1.json"
    d = json.loads(vf.read_text(encoding="utf-8"))
    fails: list[str] = []
    total = 0

    # 1. positive construction
    for v in d["vectors"]:
        total += 1
        if _ref(v) != v["expected_execution_ref"]:
            fails.append(v["id"])

    # 2. closed outcome enum
    total += 1
    v0 = d["vectors"][0]
    try:
        execution_ref(decision_ref=v0["decision_ref"], action_type="p",
                      scope="s", outcome="DONE", executed_at_ms=0)
        fails.append("closed-enum (out-of-set accepted)")
    except ExecutionRefError:
        pass

    # 3 + 4. negatives
    for n in d["negatives"]:
        total += 1
        if n["must"] == "differ":
            got = _ref(n)
            if got == n["claimed_execution_ref"] or got != n["recomputes_to"]:
                fails.append(n["id"])
        elif n["must"] == "reject":
            try:
                _ref(n)
                fails.append(f"{n['id']} (accepted, should reject)")
            except ExecutionRefError:
                pass

    # 5. cross-set composition vs spend_decision_v1
    total += 1
    sd = json.loads((here.parent / "spend_decision_v1" / "spend_decision_v1.json").read_text(encoding="utf-8"))
    sd_refs = {x["expected_decision_ref"] for x in sd["vectors"]}
    used = {v["decision_ref"] for v in d["vectors"]}
    if not used.issubset(sd_refs):
        fails.append("cross-set-composition (decision_ref not from spend_decision_v1)")

    if fails:
        print(f"FAIL ({len(fails)}/{total}): {', '.join(fails)}")
        return 1
    print(f"{total}/{total} PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
