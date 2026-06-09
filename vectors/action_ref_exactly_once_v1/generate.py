"""Deterministic generator for action_ref_exactly_once_v1.

Supersets `action_ref_transactional_v0`: same `transition_hash` primitive, extended to the full
exactly-once lifecycle (PENDING / COMMITTED / REVERSED) plus the two load-bearing exactly-once
invariants — SKIP-on-retry idempotency (a re-presented COMMITTED transition reproduces the prior
`transition_hash` byte-for-byte) and action_ref replay-binding (the same logical step under a
different `action_ref` diverges).

Primitives (substrate-1, public — `algovoi-substrate` on PyPI / `@algovoi/substrate` on npm):

    action_ref      = SHA-256(JCS({ agent_id, action_type, scope, timestamp_ms }))
    transition_hash = SHA-256(JCS({ action_ref, state, transition_timestamp_ms,
                                    authority_verified_at_ms, revocation_check_at_ms }))

This script is fully deterministic and self-contained: every byte/hash is recomputed here from
fixed inputs via RFC 8785 (`rfc8785`) + SHA-256 — no clock, no UUID, no randomness, no network.
Re-running reproduces byte-identical output. Verified byte-equal to substrate's canonicaliser.

Run:  python generate.py    (writes action_ref_exactly_once_v1.json next to this file)
"""
from __future__ import annotations

import base64
import hashlib
import json
import os

import rfc8785

# ---- fixed inputs (frozen; identical to action_ref_transactional_v0's identities) ----------------
IDENTITY = {"agent_id": "agent_alpha", "action_type": "payment",
            "scope": "vauban:stark_settlement", "timestamp_ms": 1716494400000}
# A second action_ref (agent_beta, other fields identical) for the replay-binding probe.
BINDING_IDENTITY = {"agent_id": "agent_beta", "action_type": "payment",
                    "scope": "vauban:stark_settlement", "timestamp_ms": 1716494400000}


def _jcs(obj: dict) -> bytes:
    return rfc8785.dumps(obj)


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def action_ref(identity: dict) -> str:
    return _sha256_hex(_jcs(identity))


def transition_preimage(ar: str, state: str, t_ms: int, av_ms: int, rc_ms: int) -> dict:
    return {"action_ref": ar, "state": state, "transition_timestamp_ms": t_ms,
            "authority_verified_at_ms": av_ms, "revocation_check_at_ms": rc_ms}


def main() -> None:
    ar = action_ref(IDENTITY)
    ar_binding = action_ref(BINDING_IDENTITY)

    vectors = []

    def add_identity(vid, description, identity):
        b = _jcs(identity)
        vectors.append({
            "vector_id": vid, "description": description, "pair_group": "identity",
            "expectation": "reference", "preimage": dict(identity),
            "expected_jcs_bytes_b64": base64.b64encode(b).decode("ascii"),
            "expected_action_ref": _sha256_hex(b),
        })

    def add_transition(vid, description, pair_group, ar_, state, t_ms, av_ms, rc_ms,
                       different_hash_from=None, same_hash_as=None):
        pre = transition_preimage(ar_, state, t_ms, av_ms, rc_ms)
        b = _jcs(pre)
        v = {
            "vector_id": vid, "description": description, "pair_group": pair_group,
            "expectation": "reference", "preimage": pre,
            "expected_jcs_bytes_b64": base64.b64encode(b).decode("ascii"),
            "expected_transition_hash": _sha256_hex(b),
        }
        if different_hash_from:
            v["different_hash_from"] = different_hash_from
        if same_hash_as:
            v["same_hash_as"] = same_hash_as
        vectors.append(v)

    # 001 — the stable action_ref identity across the whole lifecycle.
    add_identity("action-ref-eo-v1-001",
                 "action_ref identity for the fixed preimage. Stable across the full exactly-once lifecycle.",
                 IDENTITY)

    # 002-004 — realistic exactly-once lifecycle, distinct timestamps per state.
    add_transition("action-ref-eo-v1-002",
                   "Lifecycle: PENDING. First state of the exactly-once payment lifecycle.",
                   "lifecycle", ar, "PENDING", 1716494400000, 1716494400500, 1716494400800,
                   different_hash_from=["action-ref-eo-v1-003", "action-ref-eo-v1-004"])
    add_transition("action-ref-eo-v1-003",
                   "Lifecycle: COMMITTED. The settle/commit state — the once in exactly-once.",
                   "lifecycle", ar, "COMMITTED", 1716494500000, 1716494500300, 1716494500500,
                   different_hash_from=["action-ref-eo-v1-002", "action-ref-eo-v1-004", "action-ref-eo-v1-006"])
    add_transition("action-ref-eo-v1-004",
                   "Lifecycle: REVERSED. Compensating state after a COMMITTED transition.",
                   "lifecycle", ar, "REVERSED", 1716494600000, 1716494600300, 1716494600500,
                   different_hash_from=["action-ref-eo-v1-002", "action-ref-eo-v1-003"])

    # 005 — SKIP-on-retry idempotency: identical (action_ref, state, timestamps) to 003.
    #       The retried COMMITTED reproduces 003's transition_hash byte-for-byte → no second effect.
    add_transition("action-ref-eo-v1-005",
                   "SKIP-on-retry idempotency: a re-presented COMMITTED transition with IDENTICAL "
                   "action_ref, state and timestamps to 003. Reproduces 003's transition_hash exactly "
                   "(the exactly-once guarantee: a retry is byte-identical, never a new effect).",
                   "idempotency", ar, "COMMITTED", 1716494500000, 1716494500300, 1716494500500,
                   same_hash_as=["action-ref-eo-v1-003"])

    # 006 — replay / action_ref binding: COMMITTED under a DIFFERENT action_ref, same state+timestamps as 003.
    add_transition("action-ref-eo-v1-006",
                   "Replay / action_ref binding: COMMITTED under a DIFFERENT action_ref but identical "
                   "state and timestamps to 003. Diverges from 003 — transition_hash is bound to its "
                   "action_ref, so a replay under another identity cannot collide.",
                   "binding", ar_binding, "COMMITTED", 1716494500000, 1716494500300, 1716494500500,
                   different_hash_from=["action-ref-eo-v1-003"])

    pair_invariants = [
        {"id": "pair-eo-001", "type": "different_hash_from",
         "description": "lifecycle state distinctness: PENDING != COMMITTED (same action_ref, distinct per-state)",
         "left": "action-ref-eo-v1-002", "right": "action-ref-eo-v1-003"},
        {"id": "pair-eo-002", "type": "different_hash_from",
         "description": "lifecycle state distinctness: COMMITTED != REVERSED",
         "left": "action-ref-eo-v1-003", "right": "action-ref-eo-v1-004"},
        {"id": "pair-eo-003", "type": "same_hash_as",
         "description": "SKIP-on-retry idempotency: a re-presented COMMITTED reproduces the prior "
                        "transition_hash byte-for-byte (the exactly-once invariant)",
         "left": "action-ref-eo-v1-003", "right": "action-ref-eo-v1-005"},
        {"id": "pair-eo-004", "type": "different_hash_from",
         "description": "action_ref replay-binding: identical state+timestamps under a different "
                        "action_ref produce a different transition_hash",
         "left": "action-ref-eo-v1-003", "right": "action-ref-eo-v1-006"},
        {"id": "pair-eo-005", "type": "different_hash_from",
         "description": "identity-vs-transition: the action_ref digest and any transition_hash are byte-distinct",
         "left": "action-ref-eo-v1-001", "right": "action-ref-eo-v1-003"},
    ]

    out = {
        "schema_version": "1.0",
        "artefact_id": "action-ref-exactly-once-conformance-v1",
        "published_at": "2026-06-09T00:00:00Z",
        "canon_version": "jcs-rfc8785-v1",
        "canonicalizer": "rfc8785@0.1.4 (Python) / canonicalize@3.0.0 (TypeScript) / gowebpki/jcs v1.0.1 (Go) / cyberphone/json-canonicalization (Java) / serde_jcs@0.2.0 (Rust)",
        "hash": "SHA-256, lowercase hex",
        "supersets": "action_ref_transactional_v0",
        "anchored_to": {
            "primitive_identity": "action_ref = SHA-256(JCS({agent_id, action_type, scope, timestamp_ms}))",
            "primitive_transition": "transition_hash = SHA-256(JCS({action_ref, state, transition_timestamp_ms, authority_verified_at_ms, revocation_check_at_ms}))",
            "load_bearing_invariants": [
                "action_ref is byte-stable across every state of the exactly-once lifecycle.",
                "Each lifecycle state (PENDING / COMMITTED / REVERSED) yields a distinct transition_hash under identical other-field values.",
                "SKIP-on-retry: a re-presented transition with an identical (action_ref, state, timestamp) tuple reproduces the prior transition_hash byte-for-byte — a retry is idempotent, never a second effect.",
                "transition_hash is bound to its action_ref: an identical state+timestamps under a different action_ref produces a different transition_hash (replay under another identity cannot collide).",
                "All timestamp fields are epoch-millisecond integers (Substrate Rule 2); RFC 3339 string forms are rejected at validation time.",
            ],
            "spec_authorship": "AlgoVoi-authored. Supersets the transactional action_ref lifecycle (action_ref_transactional_v0); extends authorisation/settlement/refund to the full exactly-once vocabulary PENDING/COMMITTED/REVERSED with the SKIP-on-retry idempotency invariant.",
        },
        "fixed_identity_preimage": dict(IDENTITY),
        "binding_identity_preimage": dict(BINDING_IDENTITY),
        "vectors": vectors,
        "pair_invariants": pair_invariants,
    }

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "action_ref_exactly_once_v1.json")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    print(f"wrote {len(vectors)} vectors + {len(pair_invariants)} pair invariants -> {path}")
    for v in vectors:
        h = v.get("expected_transition_hash") or v.get("expected_action_ref")
        print(f"  {v['vector_id']:24s} {v['pair_group']:12s} {h}")


if __name__ == "__main__":
    main()
