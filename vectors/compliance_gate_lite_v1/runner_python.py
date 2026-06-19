"""
compliance_gate_lite_v1 runner (Python).

Validates the payer_ref + 3 verdict vectors + 5 negatives + 2 invariants in
compliance_gate_lite_v1.json using algovoi-substrate (>=0.4.0) on PyPI. The open,
content-addressed compliance gate:

    payer_ref = "sha256:" + SHA-256(JCS({address, network}))            (no PII out)
    gate_ref  = "sha256:" + SHA-256(JCS({payer_ref, subject_ref, verdict}))

verdict is a closed enumeration {ALLOW, REFER, DENY}; subject_ref is a pinned ref
(policy_bound_ref / settlement-action binding_ref / retention_chain ref) imported by
hash. A verdict bound under one policy snapshot does not recompute under a rotated one.

Usage:
    pip install algovoi-substrate>=0.4.0
    python runner_python.py [compliance_gate_lite_v1.json]
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from algovoi_substrate import sha256_jcs

VERDICTS = ("ALLOW", "REFER", "DENY")
_REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class _GateError(ValueError):
    pass


def _prefixed(value) -> str:
    return "sha256:" + sha256_jcs(value)


def payer_ref(network, address) -> str:
    if not isinstance(network, str) or not network or not isinstance(address, str) or not address:
        raise _GateError("network and address must be non-empty strings")
    return _prefixed({"address": address, "network": network})


def gate_ref(verdict, payer_ref_value, subject_ref) -> str:
    if verdict not in VERDICTS:
        raise _GateError(f"verdict must be one of {VERDICTS}")
    for name, val in (("payer_ref", payer_ref_value), ("subject_ref", subject_ref)):
        if not isinstance(val, str) or not _REF_RE.match(val):
            raise _GateError(f"{name} must be a sha256: ref")
    return _prefixed({"payer_ref": payer_ref_value, "subject_ref": subject_ref, "verdict": verdict})


def main() -> int:
    here = Path(__file__).parent
    vf = Path(sys.argv[1]) if len(sys.argv) > 1 else here / "compliance_gate_lite_v1.json"
    d = json.loads(vf.read_text(encoding="utf-8"))
    fails: list[str] = []

    for name, exp in d["expected_payer_ref"].items():
        p = d["payers"][name]
        if payer_ref(p["network"], p["address"]) != exp:
            fails.append(f"payer_ref[{name}]")

    for v in d["vectors"]:
        if gate_ref(v["verdict"], v["payer_ref"], v["subject_ref"]) != v["expected_gate_ref"]:
            fails.append(v["id"])

    for n in d["negatives"]:
        if n["must"] == "reject":
            try:
                gate_ref(n["verdict"], n["payer_ref"], n["subject_ref"])
                fails.append(f"{n['id']} (accepted, should reject)")
            except _GateError:
                pass
        else:
            got = gate_ref(n["verdict"], n["payer_ref"], n["subject_ref"])
            if got == n["claimed_gate_ref"]:
                fails.append(f"{n['id']} (tamper not detected)")
            elif "recomputes_to" in n and got != n["recomputes_to"]:
                fails.append(n["id"])

    p0 = d["vectors"][0]
    if len({gate_ref(w, p0["payer_ref"], p0["subject_ref"]) for w in VERDICTS}) != 3:
        fails.append("verdict-distinctness")
    try:
        gate_ref("BLOCK", p0["payer_ref"], p0["subject_ref"])
        fails.append("closed-enum (out-of-set accepted)")
    except _GateError:
        pass

    total = len(d["expected_payer_ref"]) + len(d["vectors"]) + len(d["negatives"]) + 2
    if fails:
        print(f"FAIL ({len(fails)}/{total}): {', '.join(fails)}")
        return 1
    print(f"{total}/{total} PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
