"""
spend_decision_v1 runner (Python).

Validates the commercial Spend Guardrail decision chain construction:

    decision_ref     = "sha256:" + SHA-256(JCS({agent_ref, mandate_ref, policy_bound_ref, verdict}))
    prev_entry_hash  = "sha256:" + SHA-256(JCS(previous_decision_payload))

``verdict`` is the closed enum {ALLOW, DENY, REFER}. ALLOW/DENY ``decision_ref`` are byte-identical to
spend_guardrail_lite_v1 (the open lite tier composes into the commercial product); REFER is the
commercial review verdict. The chain section anchors that each entry's ``prev_entry_hash`` is the JCS
hash of the entry before it (a single altered or dropped decision breaks the chain from that point).

    pip install algovoi-substrate>=0.4.0
    python runner_python.py [spend_decision_v1.json]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from algovoi_substrate import sha256_jcs

VERDICTS = ("ALLOW", "DENY", "REFER")


def _prefixed(value) -> str:
    return "sha256:" + sha256_jcs(value)


def decision_ref(verdict, agent_ref, mandate_ref, policy_bound_ref) -> str:
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {VERDICTS}")
    return _prefixed({"agent_ref": agent_ref, "mandate_ref": mandate_ref,
                      "policy_bound_ref": policy_bound_ref, "verdict": verdict})


def main() -> int:
    here = Path(__file__).parent
    vf = Path(sys.argv[1]) if len(sys.argv) > 1 else here / "spend_decision_v1.json"
    d = json.loads(vf.read_text(encoding="utf-8"))
    fails: list[str] = []

    # 1. decision_ref construction (incl REFER)
    for v in d["vectors"]:
        got = decision_ref(v["verdict"], v["agent_ref"], v["mandate_ref"], v["policy_bound_ref"])
        if got != v["expected_decision_ref"]:
            fails.append(v["id"])

    # 2. closed enum
    v0 = d["vectors"][0]
    try:
        decision_ref("BLOCK", v0["agent_ref"], v0["mandate_ref"], v0["policy_bound_ref"])
        fails.append("closed-enum (out-of-set accepted)")
    except ValueError:
        pass

    # 3. chain linkage: each entry's prev_entry_hash == JCS hash of the prior payload; entry_hash recomputes
    prev = None
    for c in d["chain"]:
        if c["payload"].get("prev_entry_hash") != prev:
            fails.append(f"chain-prev@{c['seq']}")
        h = _prefixed(c["payload"])
        if h != c["entry_hash"]:
            fails.append(f"chain-hash@{c['seq']}")
        prev = h

    total = len(d["vectors"]) + 1 + len(d["chain"])
    if fails:
        print(f"FAIL ({len(fails)}/{total}): {', '.join(fails)}")
        return 1
    print(f"{total}/{total} PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
