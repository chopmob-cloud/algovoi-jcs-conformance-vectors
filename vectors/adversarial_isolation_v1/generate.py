"""Deterministic generator for adversarial_isolation_v1.

Failure-isolation conformance vectors for the substrate-1 primitives: each vector is a valid
canonical input with ONE field mutated, isolating a single rejection. Two separated claims:

  Claim 1 (bytes, 8-lang): every input — valid control and mutated alike — canonicalises to its
    published `input_jcs_bytes_b64` / `input_content_sha256` byte-for-byte. The adversarial input
    is itself a real, reproducible JSON object that all conformant implementations agree on; it is
    the *validation*, not the canonicalisation, that rejects it.

  Claim 2 (rejection PoR): the named substrate-1 check (`transition_preimage` / `action_ref` /
    `audit_chain`) MUST raise on the mutated input. Attested on the reference implementation (the
    substrate2 conformance gate + runner_python.py here). Explicitly NOT an 8-lang byte claim.

Checks exercised (substrate-1, public):
  - transition_preimage  -> TransactionalError   (substrate.transactional)
  - action_ref           -> ActionRefError       (substrate.action)
  - audit_chain          -> AuditChainError       (substrate.audit, verify_audit_chain)

Fully deterministic and self-contained: RFC 8785 (`rfc8785`) + SHA-256, no clock/UUID/randomness.

Run:  python generate.py    (writes adversarial_isolation_v1.json next to this file)
"""
from __future__ import annotations

import base64
import hashlib
import json
import os

import rfc8785

AR = "7528529a8be2044488e603b7913efaa4f83620dbcc63010d4a1478cf7e9a473c"        # valid 64-hex action_ref
AR_BAD_HEX = "g" * 64                                                          # 64 chars, not hex
AR_SHORT = "abcd1234"                                                          # too short


def _b(obj):
    cb = rfc8785.dumps(obj)
    return base64.b64encode(cb).decode("ascii"), hashlib.sha256(cb).hexdigest()


def _valid_transition(state="COMMITTED", t=1716494500000, av=1716494500300, rc=1716494500500, ar=AR):
    return {"action_ref": ar, "state": state, "transition_timestamp_ms": t,
            "authority_verified_at_ms": av, "revocation_check_at_ms": rc}


def _valid_identity():
    return {"agent_id": "agent_alpha", "action_type": "payment",
            "scope": "vauban:stark_settlement", "timestamp_ms": 1716494400000}


def _audit_chain():
    """A valid 2-row content_hash/prev_hash chain (substrate.audit wire shape)."""
    p0 = {"event": "issue", "n": 1}
    p1 = {"event": "settle", "n": 2}
    ch0 = hashlib.sha256(rfc8785.dumps(p0)).hexdigest()
    ch1 = hashlib.sha256(rfc8785.dumps(p1)).hexdigest()
    row0 = {"chain_position": 0, "prev_hash": None, "content_hash": ch0, "payload": p0}
    row1 = {"chain_position": 1, "prev_hash": ch0, "content_hash": ch1, "payload": p1}
    return [row0, row1]


def main() -> None:
    vectors = []

    def add(vid, expectation, check, input_obj, reason=None, code=None, error=None):
        b64, sha = _b(input_obj)
        v = {"vector_id": vid, "expectation": expectation, "check": check}
        if reason:
            v["reject_reason"] = reason
        if expectation == "reject":
            v["expected_rejection"] = {"code": code, "check": check, "error": error}
            v["expected_error"] = error
        v["input"] = input_obj
        v["input_jcs_bytes_b64"] = b64
        v["input_content_sha256"] = sha
        vectors.append(v)

    # ---- control: a VALID transition the named check MUST accept (proves the runner exercises rejection) ----
    add("adv-v1-000-control", "reference", "transition_preimage", _valid_transition(),
        reason="valid transition preimage — the check MUST accept this (control)")

    # ---- transition_preimage rejections (TransactionalError) ----
    t = _valid_transition(); t["transition_timestamp_ms"] = "2026-06-09T00:00:00Z"
    add("adv-v1-001-ts-rfc3339", "reject", "transition_preimage", t,
        reason="RFC 3339 string timestamp where an epoch-millisecond integer is required (Substrate Rule 2)",
        code="REJECT_NON_INT_TIMESTAMP", error="TransactionalError")

    t = _valid_transition(); t["authority_verified_at_ms"] = -1
    add("adv-v1-002-ts-negative", "reject", "transition_preimage", t,
        reason="negative timestamp (must be non-negative)",
        code="REJECT_NEGATIVE_TIMESTAMP", error="TransactionalError")

    t = _valid_transition(); t["revocation_check_at_ms"] = True
    add("adv-v1-003-ts-bool", "reject", "transition_preimage", t,
        reason="boolean where an integer timestamp is required (bool is not an int)",
        code="REJECT_BOOL_TIMESTAMP", error="TransactionalError")

    t = _valid_transition(ar=AR_BAD_HEX)
    add("adv-v1-004-action-ref-nonhex", "reject", "transition_preimage", t,
        reason="action_ref is 64 chars but not lowercase hex",
        code="REJECT_MALFORMED_ACTION_REF", error="TransactionalError")

    t = _valid_transition(ar=AR_SHORT)
    add("adv-v1-005-action-ref-short", "reject", "transition_preimage", t,
        reason="action_ref shorter than 64 hex chars",
        code="REJECT_MALFORMED_ACTION_REF", error="TransactionalError")

    t = _valid_transition(state="")
    add("adv-v1-006-state-empty", "reject", "transition_preimage", t,
        reason="empty state string (state is byte-load-bearing and must be non-empty)",
        code="REJECT_EMPTY_STATE", error="TransactionalError")

    # ---- action_ref (identity) rejections (ActionRefError) ----
    i = _valid_identity(); i["timestamp_ms"] = "2026-06-09T00:00:00Z"
    add("adv-v1-007-identity-ts-rfc3339", "reject", "action_ref", i,
        reason="identity timestamp_ms as RFC 3339 string (Substrate Rule 1: integer ms)",
        code="REJECT_NON_INT_TIMESTAMP", error="ActionRefError")

    i = _valid_identity(); i["scope"] = ""
    add("adv-v1-008-identity-scope-empty", "reject", "action_ref", i,
        reason="empty scope string (must be a non-empty string at the canonicalisation layer)",
        code="REJECT_EMPTY_SCOPE", error="ActionRefError")

    # ---- audit_chain rejections (AuditChainError) ----
    ch = _audit_chain(); ch[1]["prev_hash"] = "0" * 64
    add("adv-v1-009-chain-prev-break", "reject", "audit_chain", ch,
        reason="row 1 prev_hash does not equal row 0 content_hash (linkage break)",
        code="REJECT_PREV_HASH_BREAK", error="AuditChainError")

    ch = _audit_chain(); ch[1]["payload"] = {"event": "settle", "n": 999}  # content changed, content_hash stale
    add("adv-v1-010-chain-content-mismatch", "reject", "audit_chain", ch,
        reason="row 1 payload mutated but content_hash left stale (content_hash != sha256(jcs(payload)))",
        code="REJECT_CONTENT_HASH_MISMATCH", error="AuditChainError")

    ch = _audit_chain(); ch[1]["chain_position"] = 5
    add("adv-v1-011-chain-wrong-position", "reject", "audit_chain", ch,
        reason="row 1 chain_position is 5, not its ordinal 1",
        code="REJECT_POSITION", error="AuditChainError")

    rejects = [v for v in vectors if v["expectation"] == "reject"]
    out = {
        "schema_version": "1.0",
        "artefact_id": "adversarial-isolation-conformance-v1",
        "published_at": "2026-06-09T00:00:00Z",
        "canon_version": "jcs-rfc8785-v1",
        "canonicalizer": "rfc8785@0.1.4 (Python) / canonicalize@3.0.0 (TypeScript) / gowebpki/jcs v1.0.1 (Go) / cyberphone/json-canonicalization (Java) / serde_jcs@0.2.0 (Rust)",
        "hash": "SHA-256, lowercase hex",
        "claims": {
            "claim_1_bytes_8lang": "Every `input` (control + mutated) canonicalises to input_jcs_bytes_b64 / input_content_sha256 byte-for-byte across 8 independent RFC 8785 implementations. The adversarial input is a real, reproducible object; canonicalisation does not reject it.",
            "claim_2_rejection_por": "The named substrate-1 check (transition_preimage / action_ref / audit_chain) raises on every mutated input, and ACCEPTS the control. Attested on the reference implementation only (substrate2 gate + runner_python.py). NOT an 8-lang byte claim.",
        },
        "checks": {
            "transition_preimage": "substrate.transactional.transition_preimage -> TransactionalError",
            "action_ref": "substrate.action.action_ref_object -> ActionRefError",
            "audit_chain": "substrate.audit.verify_audit_chain -> AuditChainError",
        },
        "vector_count": len(vectors),
        "reject_count": len(rejects),
        "control_count": len(vectors) - len(rejects),
        "vectors": vectors,
    }

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "adversarial_isolation_v1.json")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    print(f"wrote {len(vectors)} vectors ({len(rejects)} reject + {len(vectors)-len(rejects)} control) -> {path}")
    for v in vectors:
        tag = v["expected_rejection"]["code"] if v["expectation"] == "reject" else "CONTROL(accept)"
        print(f"  {v['vector_id']:34s} {v['check']:20s} {tag}")


if __name__ == "__main__":
    main()
