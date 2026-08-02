"""Generate the atb_trust_v1 conformance vectors (run with a python that has algovoi_atb[keystone])."""
from __future__ import annotations

import json
from pathlib import Path

from algovoi_atb import keystone as k

PASSPORT = "sha256:b3594e33998af01bd1ad208172c5c1ac586daa8c75781379f034d97e50b1a9be"
TS = 1716460800000


class P:
    def __init__(self, pid, refused, ch):
        self.profile_id, self.refused, self.challenge = pid, refused, ch


class R:
    def __init__(self, profiles, score, passed):
        self.profiles, self.score, self.passed = profiles, score, passed


def emit(subject_kwargs, profiles, score, passed):
    run = R(profiles, score, passed)
    return k.keystone_refs_from_run(run, evaluated_at_ms=TS, **subject_kwargs)


def main() -> None:
    scenarios = [
        ("tq-trusted", {"passport_ref": PASSPORT},
         [P("injection", True, {"amt": 5}), P("cheap", False, {"amt": 1})], 0.95, True),
        ("tq-provisional", {"passport_ref": PASSPORT},
         [P("injection", True, {"amt": 5}), P("spoof", True, {"amt": 9})], 0.75, True),
        ("tq-untrusted", {"passport_ref": PASSPORT},
         [P("injection", False, {"amt": 5})], 0.40, False),
        ("tq-opaque-subject", {"agent_id_hash": "abc123"},
         [P("injection", True, {"amt": 5})], 0.95, True),
    ]
    vectors = []
    for vid, subj, profs, score, passed in scenarios:
        out = emit(subj, profs, score, passed)
        vectors.append({
            "id": vid,
            "subject_kind": out["subject_kind"],
            "subject_ref": out["subject_ref"],
            "trials": [{"profile_id": p.profile_id,
                        "challenge": p.challenge,
                        "decision": "REFUSE" if p.refused else "PAY",
                        "evaluated_at_ms": TS,
                        "trial_ref": t["trial_ref"]}
                       for p, t in zip(profs, out["trials"])],
            "score": score, "passed": passed,
            "expected_trust_outcome": out["trust_outcome"],
            "expected_atb_trust_ref": out["atb_trust_ref"],
        })

    # Negatives: a tamper on any field must diverge the trust ref.
    base = next(v for v in vectors if v["id"] == "tq-trusted")
    negs = [
        {"id": "neg-decision-flip", "family": "decision",
         "note": "flipping a trial decision REFUSE->PAY changes its trial_ref and the trust_ref",
         "mutate": {"trial_index": 0, "decision": "PAY"}},
        {"id": "neg-outcome-swap", "family": "trust_outcome",
         "note": "claiming TRUSTED for an UNTRUSTED verdict diverges",
         "mutate": {"trust_outcome": "UNTRUSTED"}},
    ]
    Path("atb_trust_v1.json").write_text(json.dumps({
        "set": "atb_trust_v1",
        "schema_version": "1",
        "description": "ATB verdict as a Keystone trust query. atb_trust_ref = trust_query_ref "
                       "= sha256: + SHA-256(JCS({subject_refs, trust_outcome})). subject_refs = "
                       "[passport_ref (or opaque agent_id_hash), then one atb_trial_ref per profile "
                       "(alias of execution_ref)]. Byte-identical to the canonical trust_query_ref.",
        "canonicalizer": "rfc8785-jcs + sha256, prefixed 'sha256:'",
        "fields": ["subject_refs", "trust_outcome"],
        "trust_outcomes": list(k.TRUST_OUTCOMES),
        "base_for_negatives": base["id"],
        "vectors": vectors,
        "negatives": negs,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"wrote atb_trust_v1.json: {len(vectors)} positives, {len(negs)} negatives")


if __name__ == "__main__":
    main()
