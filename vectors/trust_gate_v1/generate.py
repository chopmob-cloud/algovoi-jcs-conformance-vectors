#!/usr/bin/env python3
"""Generate trust_gate_v1.json -- the trust-gate deny decision table.

Rule source (verbatim): gateway/app/routers/verify.py
  _TRUST_GATE_DENY = {
    "block_untrusted": {"UNTRUSTED"},
    "require_trusted": {"UNTRUSTED", "PROVISIONAL", "INSUFFICIENT_EVIDENCE"},
  }
  _trust_gate_blocks(mode, verdict): off/None/unknown mode -> never blocks
  (fail-open on the mode); otherwise verdict in the mode's deny set.

This is a behavioural conformance set (a decision table), not a JCS-hash set:
the invariant is that every implementation computes the SAME allow/deny for the
full verdict x mode matrix plus the fail-open edges.

    python generate.py
"""
from __future__ import annotations
import json
from pathlib import Path

DENY = {
    "block_untrusted": {"UNTRUSTED"},
    "require_trusted": {"UNTRUSTED", "PROVISIONAL", "INSUFFICIENT_EVIDENCE"},
}
VERDICTS = ["TRUSTED", "PROVISIONAL", "INSUFFICIENT_EVIDENCE", "UNTRUSTED"]
MODES = ["off", "block_untrusted", "require_trusted"]


def blocks(mode, verdict) -> bool:
    if not mode or mode == "off":
        return False
    return verdict in DENY.get(mode, set())


vectors = []
for mode in MODES:
    for verdict in VERDICTS:
        vectors.append({
            "id": f"tg-{mode}-{verdict.lower()}",
            "mode": mode,
            "verdict": verdict,
            "expected_blocks": blocks(mode, verdict),
        })
# Fail-open edges (security-relevant: the gate must never fail CLOSED unexpectedly,
# and must never fail OPEN for a recognised deny case -- both directions matter).
vectors.append({"id": "tg-null-mode", "mode": None, "verdict": "UNTRUSTED",
                "expected_blocks": False, "note": "None mode is fail-open on the mode"})
vectors.append({"id": "tg-unknown-mode", "mode": "strict_maximal", "verdict": "UNTRUSTED",
                "expected_blocks": False, "note": "unknown mode is fail-open on the mode"})
vectors.append({"id": "tg-unknown-verdict-require-trusted", "mode": "require_trusted",
                "verdict": "UNRECOGNISED", "expected_blocks": False,
                "note": "a verdict not in the deny set is allowed"})

doc = {
    "set": "trust_gate_v1",
    "schema_version": "1",
    "description": "Trust-gate deny decision table: verdict x mode -> allow/deny, "
                   "with fail-open-on-mode edges. Behavioural conformance (not JCS).",
    "rule_source": "gateway/app/routers/verify.py:_TRUST_GATE_DENY / _trust_gate_blocks",
    "verdicts": VERDICTS,
    "modes": MODES,
    "deny_sets": {k: sorted(v) for k, v in DENY.items()},
    "vectors": vectors,
}

out = Path(__file__).parent / "trust_gate_v1.json"
out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline="\n")
print(f"wrote {out.name} ({len(vectors)} vectors)")
