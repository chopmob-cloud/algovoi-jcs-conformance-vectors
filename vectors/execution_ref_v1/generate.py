"""
Generate execution_ref_v1.json from the reference implementation.

    execution_ref = "sha256:" + SHA-256(JCS({decision_ref, action_type, scope,
                                            outcome, executed_at_ms}))

The decision_ref inputs are the byte-identical expected_decision_ref values from
spend_decision_v1 (the keystone composes: decision_ref -> execution_ref). This
set is the post-decision execution-evidence tier: it proves the executed action
is consistent with the exact decision that authorized it.

    pip install algovoi-substrate>=0.5.0 algovoi-execution-ref
    python generate.py

The execution_ref helper ships natively in algovoi-substrate 1.0.0+; until then
(and on any substrate version) the standalone algovoi-execution-ref package
provides it. The import below falls back to it, matching runner_python.py, so a
clean environment can regenerate this set byte-for-byte.
"""
from __future__ import annotations

import json
from pathlib import Path

try:  # native in substrate 1.0.0+, else the standalone package provides it
    from algovoi_substrate import execution_ref
except ImportError:
    from algovoi_execution_ref import execution_ref

# decision_ref values reused verbatim from spend_decision_v1 (cross-set composition).
DEC_ALLOW = "sha256:2a444c629892f44fde1bd004aba9be01dd6cc7fe251eecdd545b82dca9f0bf97"
DEC_DENY = "sha256:792a5b43e9df0fc460d6bf99d6357afafbdcf910ef1e81a340e3581bc27109cf"
DEC_REFER = "sha256:914ea5fb17d6ee423d5724f18388af003aabf64d7fb162492bcadc0d93b2a872"

# Positive vectors: (id, decision_ref, action_type, scope, outcome, executed_at_ms)
POSITIVES = [
    ("ex-allow-committed", DEC_ALLOW, "payment", "bilateral", "COMMITTED", 1716460800000),
    ("ex-allow-skipped", DEC_ALLOW, "payment", "bilateral", "SKIPPED", 1716460800000),
    ("ex-allow-reversed", DEC_ALLOW, "payment", "bilateral", "REVERSED", 1716460800500),
    ("ex-refer-failed", DEC_REFER, "payment", "bilateral", "FAILED", 1716460801000),
]


def main() -> None:
    here = Path(__file__).parent
    vectors = []
    for vid, dec, at, scope, outcome, ts in POSITIVES:
        vectors.append({
            "id": vid,
            "decision_ref": dec,
            "action_type": at,
            "scope": scope,
            "outcome": outcome,
            "executed_at_ms": ts,
            "expected_execution_ref": execution_ref(
                decision_ref=dec, action_type=at, scope=scope,
                outcome=outcome, executed_at_ms=ts,
            ),
        })

    # Negatives: each demonstrates a field is byte-load-bearing. recomputes_to is
    # the ref the tampered preimage actually produces; it MUST differ from the
    # claimed (ex-allow-committed) ref.
    base = vectors[0]
    claimed = base["expected_execution_ref"]
    negatives = [
        {
            "id": "ex-neg-decision-swap",
            "family": "decision_ref",
            "claimed_execution_ref": claimed,
            "decision_ref": DEC_DENY,  # same action, different authorizing decision
            "action_type": "payment", "scope": "bilateral",
            "outcome": "COMMITTED", "executed_at_ms": 1716460800000,
            "recomputes_to": execution_ref(
                decision_ref=DEC_DENY, action_type="payment", scope="bilateral",
                outcome="COMMITTED", executed_at_ms=1716460800000),
            "must": "differ",
            "note": "execution bound to its authorizing decision: a DENY decision_ref cannot claim an ALLOW execution (consistency, not just correlation).",
        },
        {
            "id": "ex-neg-outcome-swap",
            "family": "outcome",
            "claimed_execution_ref": claimed,
            "decision_ref": DEC_ALLOW,
            "action_type": "payment", "scope": "bilateral",
            "outcome": "REVERSED", "executed_at_ms": 1716460800000,
            "recomputes_to": execution_ref(
                decision_ref=DEC_ALLOW, action_type="payment", scope="bilateral",
                outcome="REVERSED", executed_at_ms=1716460800000),
            "must": "differ",
            "note": "outcome is load-bearing: COMMITTED and REVERSED are distinct evidence.",
        },
        {
            "id": "ex-neg-timestamp-1ms",
            "family": "executed_at_ms",
            "claimed_execution_ref": claimed,
            "decision_ref": DEC_ALLOW,
            "action_type": "payment", "scope": "bilateral",
            "outcome": "COMMITTED", "executed_at_ms": 1716460800001,
            "recomputes_to": execution_ref(
                decision_ref=DEC_ALLOW, action_type="payment", scope="bilateral",
                outcome="COMMITTED", executed_at_ms=1716460800001),
            "must": "differ",
            "note": "1ms difference changes the ref; integer epoch-ms is hashed directly.",
        },
        {
            "id": "ex-neg-scope-swap",
            "family": "scope",
            "claimed_execution_ref": claimed,
            "decision_ref": DEC_ALLOW,
            "action_type": "payment", "scope": "unilateral",
            "outcome": "COMMITTED", "executed_at_ms": 1716460800000,
            "recomputes_to": execution_ref(
                decision_ref=DEC_ALLOW, action_type="payment", scope="unilateral",
                outcome="COMMITTED", executed_at_ms=1716460800000),
            "must": "differ",
            "note": "scope is load-bearing.",
        },
        {
            "id": "ex-neg-rfc3339-timestamp",
            "family": "executed_at_ms",
            "decision_ref": DEC_ALLOW,
            "action_type": "payment", "scope": "bilateral",
            "outcome": "COMMITTED", "executed_at_ms": "2026-05-23T10:40:00.000Z",
            "must": "reject",
            "note": "Substrate Rule 2: an RFC 3339 string timestamp is rejected, not converted then hashed. This is the form a non-conformant lineage uses; it cannot reproduce these bytes.",
        },
    ]

    doc = {
        "set": "execution_ref_v1",
        "schema_version": "1",
        "description": (
            "execution_ref: decision-bound execution evidence. "
            "execution_ref = \"sha256:\" + SHA-256(JCS({decision_ref, action_type, scope, outcome, executed_at_ms})). "
            "The decision_ref inputs are the byte-identical expected_decision_ref values from spend_decision_v1, "
            "so the keystone composes: passport_ref -> mandate_ref -> decision_ref (PRE-payment) -> execution_ref (POST-execution). "
            "execution_ref proves the executed action is consistent with the exact decision that authorized it, not merely correlated with an identity. "
            "outcome is the closed enum {COMMITTED, SKIPPED, FAILED, REVERSED} (SKIPPED is the exactly-once dedupe result). "
            "executed_at_ms is an epoch-millisecond integer hashed directly (Substrate Rule 2); RFC 3339 string timestamps are rejected. "
            "No raw agent_id appears: it is already bound inside decision_ref, so execution_ref is no-PII by construction."
        ),
        "canonicalizer": "rfc8785-jcs + sha256, prefixed 'sha256:'",
        "fields": ["decision_ref", "action_type", "scope", "outcome", "executed_at_ms"],
        "outcomes": ["COMMITTED", "SKIPPED", "FAILED", "REVERSED"],
        "cross_set_invariant": {
            "note": "decision_ref inputs (DEC_ALLOW/DEC_DENY/DEC_REFER) equal spend_decision_v1 sd-allow/sd-deny/sd-refer expected_decision_ref; this set is the execution tier composing onto that decision tier."
        },
        "vectors": vectors,
        "negatives": negatives,
    }

    out = here / "execution_ref_v1.json"
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {out} ({len(vectors)} vectors, {len(negatives)} negatives)")


if __name__ == "__main__":
    main()
