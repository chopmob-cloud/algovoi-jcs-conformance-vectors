"""Independently recompute atb_trust_v1 and assert byte-parity + negative divergence.

Self-contained: rfc8785 + hashlib only, no AlgoVoi package import. Every reference in
the set is recomputed from the set's own data, so agreement is a genuine independent
reproduction rather than the product library agreeing with itself.

The three constructions, all "sha256:" + SHA-256(RFC 8785 JCS bytes) of an object:

    challenge_ref  = ref(challenge)
    trial_ref      = ref({subject_ref, profile_id, challenge_ref, decision, evaluated_at_ms})
    atb_trust_ref  = ref({subject_refs, trust_outcome})
                     where subject_refs = [subject_ref] + [trial_ref per profile]

atb_trust_ref is byte-identical to the canonical trust_query_ref, which is what makes an
ATB verdict compose into the Keystone chain rather than being a parallel notion of trust.

Exit 0 iff every positive recomputes to its expected trust ref, every trial ref recomputes,
and every negative, applied to the base vector, diverges from it.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import rfc8785


def ref(obj: object) -> str:
    """sha256: + SHA-256 over the RFC 8785 canonical bytes."""
    return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def challenge_ref(challenge: object) -> str:
    return ref(challenge)


def trial_ref(subject_ref: str, profile_id: str, chal_ref: str,
              decision: str, evaluated_at_ms: int) -> str:
    return ref({
        "subject_ref": subject_ref,
        "profile_id": profile_id,
        "challenge_ref": chal_ref,
        "decision": decision,
        "evaluated_at_ms": evaluated_at_ms,
    })


def atb_trust_ref(subject_refs: list[str], trust_outcome: str) -> str:
    return ref({"subject_refs": subject_refs, "trust_outcome": trust_outcome})


def trial_refs_for(vec: dict, override: dict | None = None) -> list[str]:
    out = []
    for i, tr in enumerate(vec["trials"]):
        decision = tr["decision"]
        if override and override.get("trial_index") == i and "decision" in override:
            decision = override["decision"]
        out.append(trial_ref(vec["subject_ref"], tr["profile_id"],
                             challenge_ref(tr["challenge"]), decision, tr["evaluated_at_ms"]))
    return out


def main() -> int:
    data = json.loads((Path(__file__).parent / "atb_trust_v1.json").read_text(encoding="utf-8"))
    ok = 0

    for v in data["vectors"]:
        # every trial ref recomputes from its own inputs
        for tr, got in zip(v["trials"], trial_refs_for(v)):
            if got != tr["trial_ref"]:
                print(f"FAIL trial {v['id']}/{tr['profile_id']}: {got} != {tr['trial_ref']}")
                return 1
        # and the trust ref composes over subject + those trials
        got = atb_trust_ref([v["subject_ref"]] + trial_refs_for(v), v["expected_trust_outcome"])
        if got != v["expected_atb_trust_ref"]:
            print(f"FAIL positive {v['id']}: {got} != {v['expected_atb_trust_ref']}")
            return 1
        ok += 1

    base = next(v for v in data["vectors"] if v["id"] == data["base_for_negatives"])
    base_ref = base["expected_atb_trust_ref"]
    for neg in data["negatives"]:
        m = neg["mutate"]
        if "trust_outcome" in m:
            # same subjects, different claimed outcome
            got = atb_trust_ref([base["subject_ref"]] + trial_refs_for(base), m["trust_outcome"])
        elif "trial_index" in m:
            # flipping a trial decision must change that trial ref and therefore the trust ref
            got = atb_trust_ref([base["subject_ref"]] + trial_refs_for(base, m),
                                base["expected_trust_outcome"])
        else:
            print(f"FAIL neg {neg['id']}: unknown mutation")
            return 1
        if got == base_ref:
            print(f"FAIL negative {neg['id']}: tamper did NOT diverge")
            return 1

    print(f"PASS atb_trust_v1: {ok} positives recompute byte-for-byte, "
          f"{len(data['negatives'])} negatives diverge")
    return 0


if __name__ == "__main__":
    sys.exit(main())
