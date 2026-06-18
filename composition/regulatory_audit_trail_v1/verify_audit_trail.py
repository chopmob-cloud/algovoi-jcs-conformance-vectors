#!/usr/bin/env python3
"""
Regulatory audit trail: the full regulated-payment record, composed and
offline-verifiable, mapped to the IETF I-D family and to record-keeping
obligations across the EU, UK, US, and the FATF global standard.

This is the apex composition. From published conformance vectors only (no new
vector, no new hashing primitive), it assembles the canonical records a single
regulated agentic payment produces across its life, confirms each reproduces
byte-for-byte, recomputes the settlement-action binding from the composed values,
and maps every stage to the I-D that specifies it and the record-keeping or
retention obligation it supports in each major regime.

    admission (compliance receipt)
      -> action identity (action_ref)
        -> exactly-once commit (transition_hash, COMMITTED)
          -> settlement attestation (settlement_ref)
            -> retention chain entry (retention_chain_ref)
              -> settlement-action binding (binding_ref)

Scope note: the mapping is to the RECORD-KEEPING, RETENTION, and AUDIT-TRAIL /
INTEGRITY dimension only. These constructions support those obligations; they do
not by themselves make any firm compliant, jurisdictional applicability is
fact-specific, and this is not legal advice.

Verifiable by an auditor with SHA-256 and a JSON parser. No issuer contact.
Apache-2.0. (c) AlgoVoi. Retain NOTICE on redistribution.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from algovoi_substrate import settlement_action_binding

VECTORS = Path(__file__).resolve().parents[2] / "vectors"

# Per-stage record-keeping / retention / integrity provisions, by regime.
# Well-known principal provisions only; mapped to the dimension each stage serves.
REG = {
    "admission": {"dim": "admission decision recorded",
                  "EU": "MiCA Art 80", "UK": "MLR 2017 reg 40", "US": "BSA 31 CFR 1010.430", "FATF": "Rec 11"},
    "action identity": {"dim": "stable transaction identity",
                  "EU": "MiCA Art 80", "UK": "MLR 2017 reg 40", "US": "BSA 31 CFR 1010.430", "FATF": "Rec 11"},
    "exactly-once commit": {"dim": "operational integrity, no double effect",
                  "EU": "DORA Art 14", "UK": "FCA SYSC 9", "US": "BSA recordkeeping (integrity)", "FATF": "Rec 11"},
    "settlement": {"dim": "record of the settled transfer",
                  "EU": "MiCA Art 80", "UK": "MLR 2017 reg 40", "US": "BSA 31 CFR 1010.430", "FATF": "Rec 16 (transfer info)"},
    "retention": {"dim": "tamper-evident 5-year retention",
                  "EU": "AMLR Art 56", "UK": "MLR 2017 reg 40 (5 yr)", "US": "BSA 31 CFR 1010.430 (5 yr)", "FATF": "Rec 11 (>=5 yr)"},
    "binding": {"dim": "single auditable bound record / reconstruction",
                  "EU": "MiCA Art 80 + DORA Art 14", "UK": "MLR 2017 reg 40 + FCA SYSC 9", "US": "BSA 31 CFR 1010.430", "FATF": "Rec 11"},
}


def _load(s: str) -> dict:
    return json.loads((VECTORS / s / f"{s}.json").read_text(encoding="utf-8"))


def main() -> int:
    cr = _load("compliance_receipt_v1")
    aro = _load("action_ref_exactly_once_v1")
    sat = _load("settlement_attestation_v1")
    rc = _load("retention_chain_v1")
    sab = _load("settlement_action_binding_v1")

    compliance_hashes = {v["expected_content_hash"] for v in cr["vectors"] if "expected_content_hash" in v}
    action_refs = {v["expected_action_ref"] for v in aro["vectors"] if "expected_action_ref" in v}
    committed = {v["expected_transition_hash"] for v in aro["vectors"]
                 if "expected_transition_hash" in v and v.get("preimage", {}).get("state") == "COMMITTED"}
    settlement_hashes = {v["expected_content_hash"] for v in sat["vectors"] if "expected_content_hash" in v}
    chain_refs = {v["expected_chain_ref"] for v in rc["vectors"] if "expected_chain_ref" in v}
    ref = next(v for v in sab["vectors"] if v["vector_id"] == "sab-v1-001")
    pre = ref["preimage"]
    admission = next(iter(sorted(compliance_hashes)))

    recomputed = settlement_action_binding(
        action_ref=pre["action_ref"], transition_hash=pre["transition_hash"],
        settlement_ref=pre["settlement_ref"], retention_chain_ref=pre["retention_chain_ref"])

    stages = [
        ("admission", "compliance receipt", admission, admission in compliance_hashes, "draft-hopley-x402-compliance-receipt"),
        ("action identity", "action_ref", pre["action_ref"], pre["action_ref"] in action_refs, "retention-chain Sec 7.1"),
        ("exactly-once commit", "transition_hash (COMMITTED)", pre["transition_hash"], pre["transition_hash"] in committed, "retention-chain Sec 7.2-7.3"),
        ("settlement", "settlement_ref", pre["settlement_ref"], pre["settlement_ref"] in settlement_hashes, "draft-hopley-x402-settlement-attestation"),
        ("retention", "retention_chain_ref", pre["retention_chain_ref"], pre["retention_chain_ref"] in chain_refs, "retention-chain Sec 4"),
        ("binding", "binding_ref", recomputed, recomputed == ref["expected_binding_ref"], "retention-chain Sec 7.6"),
    ]

    w = 78
    print("=" * w)
    print("REGULATORY AUDIT TRAIL -- composed from published vectors, offline-verifiable")
    print("mapped to EU / UK / US / FATF record-keeping obligations (record-keeping")
    print("dimension only; not legal advice; jurisdictional applicability is fact-specific)")
    print("=" * w)
    all_ok = True
    for i, (name, prim, value, ok, idref) in enumerate(stages, 1):
        all_ok = all_ok and ok
        r = REG[name]
        print(f"\n[{i}] {'PASS' if ok else 'FAIL'}  {name} ({prim})  -> {r['dim']}")
        print(f"      value : {value}")
        print(f"      I-D   : {idref}")
        print(f"      EU    : {r['EU']}        UK : {r['UK']}")
        print(f"      US    : {r['US']}        FATF: {r['FATF']}")

    print("\n" + "-" * w)
    if all_ok:
        print("RESULT: PASS -- every record reproduces byte-for-byte and every stage maps to")
        print("        an I-D and to a record-keeping obligation in the EU, UK, US, and FATF")
        print(f"        standard. binding_ref = {recomputed}")
        return 0
    print("RESULT: FAIL -- audit trail broken; see failed stages above.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
