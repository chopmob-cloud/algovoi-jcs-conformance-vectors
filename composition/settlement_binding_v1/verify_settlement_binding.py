#!/usr/bin/env python3
"""
settlement_binding_v1 -- composition proof: the SETTLEMENT tier binds to the
keystone EXECUTION tier.

Proves, offline and from raw fields only (RFC 8785 JCS + SHA-256, no package
import), that:

  1. execution_ref recomputes from the committed-execution fields and equals the
     keystone's published execution_ref.
  2. the settlement attestation's settled_payment_ref IS that execution_ref
     (the settled payment binds to the action that executed, not an identity).
  3. the settlement attestation content_hash recomputes (settlement_attestation_v1 shape).
  4. a retention-chain head recomputes over the settlement attestation.
  5. execution_binding recomputes over (execution_ref, settlement_ref,
     retention_chain_ref) into one accountability reference.
  6. tamper witnesses diverge: a FAILED execution and a REVERSED settlement both
     change the chain (outcome and settlement_result are byte-load-bearing).

Run:  pip install rfc8785 ; python verify_settlement_binding.py
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import rfc8785

TRACE = Path(__file__).parent / "binding_trace.json"


def _h(obj) -> str:
    return hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def _ref(obj) -> str:
    return "sha256:" + _h(obj)


def main() -> int:
    t = json.loads(TRACE.read_text(encoding="utf-8"))
    ex = t["execution"]
    sa = t["settlement_attestation"]
    rc = t["retention_chain"]
    eb = t["execution_binding"]
    tw = t["tamper"]
    checks: list[tuple[bool, str, str]] = []

    # 1. execution tier
    execution_ref = _ref({
        "decision_ref": ex["decision_ref"],
        "action_type": ex["action_type"],
        "scope": ex["scope"],
        "outcome": ex["outcome"],
        "executed_at_ms": ex["executed_at_ms"],
    })
    checks.append((execution_ref == ex["expected_execution_ref"],
                   "execution_ref recomputes from committed-execution fields, equals the keystone execution_ref",
                   execution_ref))

    # 2. settlement bound to the executed action
    checks.append((sa["receipt"]["settled_payment_ref"] == ex["expected_execution_ref"],
                   "settlement attestation settled_payment_ref IS the execution_ref (settled payment binds to the executed action)",
                   sa["receipt"]["settled_payment_ref"]))

    # 3. settlement attestation content_hash
    settlement_content = _h(sa["receipt"])
    settlement_ref = "sha256:" + settlement_content
    checks.append((settlement_content == sa["expected_content_hash"] and settlement_ref == sa["expected_settlement_ref"],
                   "settlement attestation content_hash recomputes (settlement_attestation_v1 shape)",
                   settlement_ref))

    # 4. retention-chain head over the settlement attestation
    retention_chain_ref = _ref(rc["row"])
    checks.append((rc["row"]["content_hash"] == settlement_content
                   and retention_chain_ref == rc["expected_retention_chain_ref"],
                   "retention-chain head recomputes over the settlement attestation (audit-chain row shape)",
                   retention_chain_ref))

    # 5. one accountability reference over execution + settlement + retention
    binding_ref = _ref({
        "execution_ref": execution_ref,
        "settlement_ref": settlement_ref,
        "retention_chain_ref": retention_chain_ref,
    })
    checks.append((binding_ref == eb["expected_binding_ref"],
                   "execution_binding recomputes over (execution_ref, settlement_ref, retention_chain_ref) into one accountability reference",
                   binding_ref))

    # 6. tamper witnesses diverge
    failed_ref = _ref({**{k: ex[k] for k in ("decision_ref", "action_type", "scope", "executed_at_ms")}, "outcome": "FAILED"})
    reversed_receipt = dict(sa["receipt"], settlement_result="REVERSED")
    reversed_settlement_ref = "sha256:" + _h(reversed_receipt)
    tamper_ok = (
        failed_ref == tw["failed_execution_ref"]
        and failed_ref != execution_ref
        and reversed_settlement_ref == tw["reversed_settlement_ref"]
        and reversed_settlement_ref != settlement_ref
    )
    checks.append((tamper_ok,
                   "tamper witnesses diverge: FAILED execution and REVERSED settlement both change the chain (byte-load-bearing)",
                   "divergent"))

    bar = "-" * 74
    print("=" * 74)
    print("SETTLEMENT BINDING -- composition proof (settlement tier -> keystone execution tier)")
    print("composed from raw fields only; no new hash, no package import")
    print("=" * 74)
    npass = 0
    for i, (ok, desc, val) in enumerate(checks, 1):
        print(f"\n[{i}] {'PASS' if ok else 'FAIL'}  {desc}")
        print(f"      value : {val}")
        npass += 1 if ok else 0
    print("\n" + bar)
    print(f"PASS {npass}/{len(checks)} -- the settled payment binds to the executed action,")
    print("     capped by one execution_binding accountability reference.")
    return 0 if npass == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
