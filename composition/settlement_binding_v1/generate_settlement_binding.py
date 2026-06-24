#!/usr/bin/env python3
"""
settlement_binding_v1 composition generator.

Builds the trace that proves the SETTLEMENT tier binds to the EXECUTION tier of
the keystone: a settlement attestation whose settled_payment_ref is the exact
execution_ref the keystone produced, capped by one execution_binding accountability
reference over (execution_ref, settlement_ref, retention_chain_ref).

This is integration #1 from the keystone bolt-on map: "what settled binds to what
executed", using the execution_binding socket already shipped in algovoi-execution-ref.

No new hashing primitive: every reference is RFC 8785 JCS + SHA-256, reusing
  - the execution_ref construction (execution_ref_v1, ex-allow-committed),
  - the settlement attestation receipt shape (settlement_attestation_v1),
  - the audit-chain row shape (settlement_attestation_v1 rows 006-008),
  - execution_binding (algovoi-execution-ref).

Usage:
    pip install rfc8785
    python generate_settlement_binding.py        # writes binding_trace.json
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import rfc8785

OUT = Path(__file__).parent / "binding_trace.json"

# ---- the JCS + SHA-256 substrate (no package import; the whole dependency) ----
def _h(obj) -> str:
    """bare lowercase-hex SHA-256 over the RFC 8785 JCS bytes of obj."""
    return hashlib.sha256(rfc8785.dumps(obj)).hexdigest()

def _ref(obj) -> str:
    """content-addressed reference: 'sha256:' + JCS-SHA-256."""
    return "sha256:" + _h(obj)

# ---- keystone EXECUTION tier (exact ex-allow-committed inputs) -----------------
# decision_ref is the ALLOW decision the keystone produced (spend_decision/keystone_v1).
DECISION_REF = "sha256:2a444c629892f44fde1bd004aba9be01dd6cc7fe251eecdd545b82dca9f0bf97"
EXECUTION = {
    "decision_ref": DECISION_REF,
    "action_type": "payment",
    "scope": "bilateral",
    "outcome": "COMMITTED",
    "executed_at_ms": 1716460800000,
}
# published keystone value (execution_ref_v1 ex-allow-committed / keystone_v1):
EXPECT_EXECUTION_REF = "sha256:f6e2bfc15b085ed51c4c972de81d1c6b00f4e55b272e2aa12e56bb7c521fc65a"

# ---- settlement attestation, bound to the executed action ----------------------
# settled_payment_ref is the EXACT execution_ref the keystone produced: the
# settlement attests the payment that this committed execution authorized.
def build_settlement_receipt(settled_payment_ref: str, result: str = "SETTLED") -> dict:
    return {
        "canon_version": "jcs-rfc8785-v1",
        "jurisdiction_flags": ["UK", "EU"],
        "settled_payment_ref": settled_payment_ref,
        "settlement_amount": {"amount_minor": "100000", "asset_id": "USDC.6"},
        "settlement_chain": "ethereum:8453",
        "settlement_provider_did": "did:example:settlement-provider-1",
        "settlement_result": result,
        "settlement_timestamp_ms": 1716494400000,
    }

# ---- retention-chain head over the settlement attestation ----------------------
# Same audit-chain row shape as settlement_attestation_v1 rows 006-008.
def build_retention_head(settlement_content_hash: str) -> dict:
    return {
        "content_hash": settlement_content_hash,
        "prev_hash": "0" * 64,
        "row_number": 1,
    }


def main() -> int:
    # 1. execution tier
    execution_ref = _ref(EXECUTION)
    assert execution_ref == EXPECT_EXECUTION_REF, (
        f"execution_ref drift: {execution_ref} != {EXPECT_EXECUTION_REF}")

    # 2. settlement bound to the executed action (settled_payment_ref == execution_ref)
    receipt = build_settlement_receipt(execution_ref, "SETTLED")
    settlement_content_hash = _h(receipt)          # bare hex (settlement_attestation_v1 convention)
    settlement_ref = "sha256:" + settlement_content_hash

    # 3. retention-chain head anchoring the settlement attestation
    retention_row = build_retention_head(settlement_content_hash)
    retention_chain_ref = _ref(retention_row)

    # 4. one accountability reference over the executed action + its settlement + retention
    binding_pre = {
        "execution_ref": execution_ref,
        "settlement_ref": settlement_ref,
        "retention_chain_ref": retention_chain_ref,
    }
    binding_ref = _ref(binding_pre)

    # 5. tamper witnesses (negative): a FAILED execution diverges the whole chain
    failed_execution = dict(EXECUTION, outcome="FAILED")
    failed_execution_ref = _ref(failed_execution)
    # a REVERSED settlement diverges settlement_ref -> binding
    reversed_receipt = build_settlement_receipt(execution_ref, "REVERSED")
    reversed_settlement_ref = "sha256:" + _h(reversed_receipt)

    trace = {
        "set": "settlement_binding_v1",
        "title": "Settlement tier binds to the keystone execution tier",
        "canon_version": "jcs-rfc8785-v1",
        "summary": (
            "A settlement attestation whose settled_payment_ref is the exact "
            "execution_ref the keystone produced, capped by one execution_binding "
            "over (execution_ref, settlement_ref, retention_chain_ref). Proves the "
            "settled payment binds to the executed action that authorized it, not "
            "merely an identity. No new hashing primitive."
        ),
        "execution": {**EXECUTION, "expected_execution_ref": execution_ref},
        "settlement_attestation": {
            "receipt": receipt,
            "expected_content_hash": settlement_content_hash,
            "expected_settlement_ref": settlement_ref,
            "binds_to": "execution_ref (settled_payment_ref == execution_ref)",
        },
        "retention_chain": {
            "row": retention_row,
            "expected_retention_chain_ref": retention_chain_ref,
        },
        "execution_binding": {
            "preimage_fields": ["execution_ref", "retention_chain_ref", "settlement_ref"],
            "expected_binding_ref": binding_ref,
        },
        "tamper": {
            "failed_execution_ref": failed_execution_ref,
            "reversed_settlement_ref": reversed_settlement_ref,
            "note": (
                "failed_execution_ref != expected_execution_ref (outcome is "
                "byte-load-bearing); reversed_settlement_ref != expected_settlement_ref "
                "(settlement_result is byte-load-bearing). Either diverges binding_ref."
            ),
        },
    }
    OUT.write_text(json.dumps(trace, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("wrote", OUT.name)
    print("  execution_ref       :", execution_ref)
    print("  settlement_content  :", settlement_content_hash)
    print("  settlement_ref      :", settlement_ref)
    print("  retention_chain_ref :", retention_chain_ref)
    print("  binding_ref         :", binding_ref)
    return 0


if __name__ == "__main__":
    sys.exit(main())
