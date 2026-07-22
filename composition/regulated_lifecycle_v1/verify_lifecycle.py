#!/usr/bin/env python3
"""
Regulated Agentic Payment Lifecycle: end-to-end composition proof.

This runner proves, offline and from already-published conformance vectors
only, that the full regulated agentic-payment lifecycle composes into a single
self-verifiable chain. It introduces NO new vectors and NO new hashing
primitive: every value it asserts is the published `expected_*` output of an
existing AlgoVoi conformance set, and the final binding is recomputed with the
released `algovoi-substrate` package.

The chain:

    action identity            action_ref            (action_ref_exactly_once_v1)
      -> exactly-once state    transition_hash        (action_ref_exactly_once_v1, COMMITTED)
        -> settlement          settlement_ref         (settlement_attestation_v1, content_hash)
          -> retention chain   retention_chain_ref    (retention_chain_v1)
            -> binding         binding_ref            (settlement_action_binding_v1)

The proof is that the four inputs of settlement_action_binding_v1 (sab-v1-001)
are byte-identical to the published reference outputs of the four upstream
sets, and that recomputing binding_ref from those composed values reproduces
the published reference binding byte-for-byte.

Apache-2.0. (c) AlgoVoi. NOTICE attribution required for redistribution; see
the conformance corpus NOTICE.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from algovoi_substrate import settlement_action_binding

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent.parent / "vectors"


def _load(set_name: str) -> dict:
    path = VECTORS / set_name / f"{set_name}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _published_outputs() -> dict:
    """Collect the published expected-output values from each upstream set."""
    aro = _load("action_ref_exactly_once_v1")
    sat = _load("settlement_attestation_v1")
    rc = _load("retention_chain_v1")

    action_refs = {
        v["expected_action_ref"]
        for v in aro["vectors"]
        if "expected_action_ref" in v
    }
    committed_transitions = {
        v["expected_transition_hash"]
        for v in aro["vectors"]
        if "expected_transition_hash" in v
        and v.get("preimage", {}).get("state") == "COMMITTED"
    }
    settlement_content_hashes = {
        v["expected_content_hash"]
        for v in sat["vectors"]
        if "expected_content_hash" in v
    }
    chain_refs = {
        v["expected_chain_ref"]
        for v in rc["vectors"]
        if "expected_chain_ref" in v
    }
    return {
        "action_refs": action_refs,
        "committed_transitions": committed_transitions,
        "settlement_content_hashes": settlement_content_hashes,
        "chain_refs": chain_refs,
    }


def _binding_reference() -> dict:
    sab = _load("settlement_action_binding_v1")
    for v in sab["vectors"]:
        if v["vector_id"] == "sab-v1-001":
            return v
    raise SystemExit("sab-v1-001 reference vector not found")


# Each link maps to the regulatory obligation the I-D (draft-hopley-x402-
# retention-chain) already cites. The composition is what makes the obligation
# auditable end-to-end rather than per-primitive.
REG = {
    "action_ref": "MiCA Art 80 (transaction reconstruction: stable action identity)",
    "transition_hash": "DORA Art 14 (operational integrity: exactly-once COMMITTED state)",
    "settlement_ref": "AMLR Art 56 (record retention: the settled payment attested)",
    "retention_chain_ref": "MiCA Art 80 / DORA Art 14 (tamper-evident audit position)",
    "binding_ref": "MiCA 80 + DORA 14 + AMLR 56 (the four bound into one auditable record)",
}


def main() -> int:
    outputs = _published_outputs()
    ref = _binding_reference()
    pre = ref["preimage"]
    expected_binding = ref["expected_binding_ref"]

    checks = []

    # 1-4: every binding input is a published upstream output (non-circular:
    # the upstream sets produce these independently; the binding consumes them).
    checks.append((
        "action_ref traces to action_ref_exactly_once_v1.expected_action_ref",
        pre["action_ref"] in outputs["action_refs"],
        pre["action_ref"],
        REG["action_ref"],
    ))
    checks.append((
        "transition_hash traces to a COMMITTED action_ref_exactly_once_v1 output",
        pre["transition_hash"] in outputs["committed_transitions"],
        pre["transition_hash"],
        REG["transition_hash"],
    ))
    checks.append((
        "settlement_ref traces to settlement_attestation_v1.expected_content_hash",
        pre["settlement_ref"] in outputs["settlement_content_hashes"],
        pre["settlement_ref"],
        REG["settlement_ref"],
    ))
    checks.append((
        "retention_chain_ref traces to retention_chain_v1.expected_chain_ref",
        pre["retention_chain_ref"] in outputs["chain_refs"],
        pre["retention_chain_ref"],
        REG["retention_chain_ref"],
    ))

    # 5: the published lifecycle_trace.json manifest must agree with the vectors it
    # cites. The manifest was previously not read by this runner at all, so every
    # value in it was carried: it could name any digest, for any step, and nothing
    # here would notice. Each entry declares its own source_set and source_field, so
    # the check is generic rather than hardcoded.
    trace = json.loads((HERE / "lifecycle_trace.json").read_text(encoding="utf-8"))
    bad_steps = []
    for entry in trace["chain"]:
        published = {
            v[entry["source_field"]]
            for v in _load(entry["source_set"])["vectors"]
            if entry["source_field"] in v
        }
        if entry["value"] not in published:
            bad_steps.append(f'step {entry["step"]} ({entry["primitive"]})')
    manifest_ok = not bad_steps and trace["binding_ref"] == expected_binding
    checks.append((
        "lifecycle_trace manifest: every step value is the published output of the set it cites, "
        "and binding_ref is the published reference",
        manifest_ok,
        "all 5 steps traced" if manifest_ok else f"unverified: {bad_steps or ['binding_ref']}",
        "manifest integrity (the published chain description is itself checked)",
    ))

    # 6: recompute the binding from the composed (traced) values using the
    # released package, and match the published reference byte-for-byte.
    recomputed = settlement_action_binding(
        action_ref=pre["action_ref"],
        transition_hash=pre["transition_hash"],
        settlement_ref=pre["settlement_ref"],
        retention_chain_ref=pre["retention_chain_ref"],
    )
    checks.append((
        "binding_ref recomputed from the composed chain matches the published reference",
        recomputed == expected_binding,
        recomputed,
        REG["binding_ref"],
    ))

    width = 72
    print("=" * width)
    print("REGULATED AGENTIC PAYMENT LIFECYCLE -- composition proof")
    print("composed from published vectors only; no new vectors, no new hash")
    print("=" * width)
    all_ok = True
    for i, (desc, ok, value, reg) in enumerate(checks, 1):
        status = "PASS" if ok else "FAIL"
        all_ok = all_ok and ok
        print(f"\n[{i}] {status}  {desc}")
        print(f"      value : {value}")
        print(f"      maps  : {reg}")

    print("\n" + "-" * width)
    if all_ok:
        print("RESULT: PASS -- the full lifecycle composes end-to-end, byte-for-byte.")
        print("        action_ref -> transition_hash (COMMITTED) -> settlement_ref")
        print("        -> retention_chain_ref -> binding_ref, every link a published")
        print(f"        conformance output, final binding_ref = {expected_binding}")
        return 0
    print("RESULT: FAIL -- composition broken; see failed checks above.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
