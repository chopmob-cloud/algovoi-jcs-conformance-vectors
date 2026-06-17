"""Deterministic generator for settlement_action_binding_v1.

Closes the post-settlement accountability gap: a settlement attestation proves a
*payment* occurred; on its own it does not prove *which verified agent action* the
payment corresponds to, nor that the correspondence is recorded in a tamper-evident
chain. `binding_ref` binds four already-published substrate artifacts into one record:

    binding_ref = "sha256:" + SHA-256(JCS({
        action_ref,            # verified agent-action identity
        transition_hash,       # the COMMITTED lifecycle transition (the "once")
        settlement_ref,        # settlement attestation content_hash
        retention_chain_ref,   # tamper-evident chain position recording it
    }))

No new hashing primitive: the binding is the substrate's existing JCS + SHA-256 over
the four references. The output carries the "sha256:" prefix, consistent with
`retention_chain_ref`. Because action_ref / transition_hash are computed from
epoch-millisecond-integer preimages (Substrate Rule 2), any upstream RFC 3339 string
timestamp yields a different action_ref -> a different binding: a non-conformant
lineage cannot reproduce the binding bytes (see adversarial_isolation_v1
adv-v1-001-ts-rfc3339).

Anchors are reused verbatim from already-published sets so this set composes with them:
- action_ref / transition_hash: action_ref_exactly_once_v1 (agent_alpha identity; COMMITTED
  003 and PENDING 002 transition_hashes; agent_beta binding identity).
- settlement_ref: settlement_attestation_v1 (content_hash of vectors 001 / 002).
- retention_chain_ref: retention_chain_v1 (chain_ref of vectors 001 / 002).

Fully deterministic and self-contained: every byte/hash recomputed here from fixed inputs
via RFC 8785 + SHA-256 -- no clock, no UUID, no randomness, no network. Re-running
reproduces byte-identical output. Verified byte-equal to algovoi-substrate's
settlement_action_binding().

Run:  python generate.py    (writes settlement_action_binding_v1.json next to this file)
"""
from __future__ import annotations

import base64
import hashlib
import json
import os

import rfc8785

# ---- fixed anchors (frozen; reused verbatim from published sets) -----------------------------
# action_ref / transition_hash -- action_ref_exactly_once_v1
ACTION_REF = "7528529a8be2044488e603b7913efaa4f83620dbcc63010d4a1478cf7e9a473c"        # agent_alpha identity
ACTION_REF_BETA = "57e861cb0929fe602823a15e2bc5a5587f0b9c3bd39147baa49819dd014c56a6"   # agent_beta (binding probe)
TH_COMMITTED = "f49faa7c4f82bd842705374311f5f6af073826539d519d0b65de3263258eac5f"      # eo-v1-003 COMMITTED
TH_PENDING = "0957638b64c790292c11d90e9ae15576a6454f37f23a0aade222acf9e2ea18b0"        # eo-v1-002 PENDING
# settlement_ref -- settlement_attestation_v1 content_hash
SETTLEMENT_REF_A = "0ead75bfe7fc74cc0421124903e56cb5c5006d02c393231a1d5f260fa87e96d3"  # settlement-attestation-v1-001
SETTLEMENT_REF_B = "e7777a9a77a9c3f02339594395bfb2620e07edc62d3dcb48c4f2e82a8c37a1c4"  # settlement-attestation-v1-002
# retention_chain_ref -- retention_chain_v1 chain_ref ("sha256:"-prefixed)
RETENTION_CHAIN_REF_A = "sha256:d23aeb006c5f3db9dd96315916410393904f56c4c871593065eb73b783fff35f"  # retention-chain-v1-001
RETENTION_CHAIN_REF_B = "sha256:43f888f00ea70e38fb8e38c205219b3fff51a90c62197d890b9f270f0f81fe42"  # retention-chain-v1-002


def _jcs(obj: dict) -> bytes:
    return rfc8785.dumps(obj)


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def binding_preimage(action_ref: str, transition_hash: str,
                     settlement_ref: str, retention_chain_ref: str) -> dict:
    return {"action_ref": action_ref, "transition_hash": transition_hash,
            "settlement_ref": settlement_ref, "retention_chain_ref": retention_chain_ref}


def main() -> None:
    vectors = []

    def add(vid, description, pair_group, ar, th, sref, cref,
            different_hash_from=None, same_hash_as=None):
        pre = binding_preimage(ar, th, sref, cref)
        b = _jcs(pre)
        digest = _sha256_hex(b)
        v = {
            "vector_id": vid, "description": description, "pair_group": pair_group,
            "expectation": "reference", "preimage": pre,
            "expected_jcs_bytes_b64": base64.b64encode(b).decode("ascii"),
            "expected_content_sha256": digest,
            "expected_binding_ref": "sha256:" + digest,
        }
        if different_hash_from:
            v["different_hash_from"] = different_hash_from
        if same_hash_as:
            v["same_hash_as"] = same_hash_as
        vectors.append(v)

    # 001 -- the canonical reference binding: verified action (COMMITTED) <-> settlement <-> chain.
    add("sab-v1-001",
        "Reference binding: action_ref + COMMITTED transition_hash + settlement_ref + "
        "retention_chain_ref bound into one binding_ref. The canonical post-settlement record.",
        "reference", ACTION_REF, TH_COMMITTED, SETTLEMENT_REF_A, RETENTION_CHAIN_REF_A)

    # 002 -- binding stability / idempotency: identical inputs reproduce 001 byte-for-byte.
    add("sab-v1-002",
        "Binding stability: the same (action_ref, transition_hash, settlement_ref, "
        "retention_chain_ref) re-presented reproduces 001's binding_ref byte-for-byte "
        "(re-derivation is idempotent, never a second binding).",
        "stability", ACTION_REF, TH_COMMITTED, SETTLEMENT_REF_A, RETENTION_CHAIN_REF_A,
        same_hash_as=["sab-v1-001"])

    # 003 -- settlement-binding: a different settlement_ref diverges (a settlement cannot be
    #        re-pointed to another action's binding).
    add("sab-v1-003",
        "Settlement-binding: identical action/transition/chain but a DIFFERENT settlement_ref "
        "produces a different binding_ref -- a settlement cannot be re-pointed to another "
        "action's record.",
        "settlement", ACTION_REF, TH_COMMITTED, SETTLEMENT_REF_B, RETENTION_CHAIN_REF_A,
        different_hash_from=["sab-v1-001"])

    # 004 -- action-binding: a different action_ref diverges (an action cannot claim another's
    #        settlement).
    add("sab-v1-004",
        "Action-binding: identical transition/settlement/chain but a DIFFERENT action_ref "
        "produces a different binding_ref -- an action cannot claim another identity's "
        "settlement. (Also: an RFC 3339 timestamp upstream changes action_ref, so a "
        "non-conformant lineage cannot reproduce 001.)",
        "action", ACTION_REF_BETA, TH_COMMITTED, SETTLEMENT_REF_A, RETENTION_CHAIN_REF_A,
        different_hash_from=["sab-v1-001"])

    # 005 -- state-binding: only the exact COMMITTED transition binds; a PENDING transition_hash
    #        diverges (an unsettled state cannot masquerade as settled-bound).
    add("sab-v1-005",
        "State-binding: identical action/settlement/chain but the PENDING transition_hash "
        "(not COMMITTED) produces a different binding_ref -- only the exact COMMITTED "
        "transition binds; a non-committed state cannot masquerade as settled-bound.",
        "state", ACTION_REF, TH_PENDING, SETTLEMENT_REF_A, RETENTION_CHAIN_REF_A,
        different_hash_from=["sab-v1-001"])

    # 006 -- chain-binding: a different retention_chain_ref diverges (the chain position recording
    #        the record is load-bearing).
    add("sab-v1-006",
        "Chain-binding: identical action/transition/settlement but a DIFFERENT "
        "retention_chain_ref produces a different binding_ref -- the tamper-evident chain "
        "position recording the record is load-bearing.",
        "chain", ACTION_REF, TH_COMMITTED, SETTLEMENT_REF_A, RETENTION_CHAIN_REF_B,
        different_hash_from=["sab-v1-001"])

    pair_invariants = [
        {"id": "pair-sab-001", "type": "same_hash_as",
         "description": "binding stability: re-derivation with identical inputs reproduces the "
                        "binding_ref byte-for-byte",
         "left": "sab-v1-001", "right": "sab-v1-002"},
        {"id": "pair-sab-002", "type": "different_hash_from",
         "description": "settlement-binding: a different settlement_ref diverges",
         "left": "sab-v1-001", "right": "sab-v1-003"},
        {"id": "pair-sab-003", "type": "different_hash_from",
         "description": "action-binding: a different action_ref diverges",
         "left": "sab-v1-001", "right": "sab-v1-004"},
        {"id": "pair-sab-004", "type": "different_hash_from",
         "description": "state-binding: a non-COMMITTED transition_hash diverges",
         "left": "sab-v1-001", "right": "sab-v1-005"},
        {"id": "pair-sab-005", "type": "different_hash_from",
         "description": "chain-binding: a different retention_chain_ref diverges",
         "left": "sab-v1-001", "right": "sab-v1-006"},
    ]

    out = {
        "schema_version": "1.0",
        "artefact_id": "settlement-action-binding-conformance-v1",
        "published_at": "2026-06-18T00:00:00Z",
        "canon_version": "jcs-rfc8785-v1",
        "canonicalizer": "rfc8785@0.1.4 (Python) / canonicalize@3.0.0 (TypeScript) / gowebpki/jcs v1.0.1 (Go) / cyberphone/json-canonicalization (Java) / serde_jcs@0.2.0 (Rust)",
        "hash": "SHA-256, lowercase hex; binding_ref carries the 'sha256:' algorithm prefix",
        "composes_with": "action_ref_exactly_once_v1 (action_ref + transition_hash); settlement_attestation_v1 (settlement_ref = content_hash); retention_chain_v1 (retention_chain_ref)",
        "anchored_to": {
            "primitive_binding": "binding_ref = 'sha256:' + SHA-256(JCS({action_ref, transition_hash, settlement_ref, retention_chain_ref}))",
            "load_bearing_invariants": [
                "Binding stability: identical (action_ref, transition_hash, settlement_ref, retention_chain_ref) reproduces the same binding_ref byte-for-byte.",
                "Settlement-binding: changing settlement_ref changes binding_ref (a settlement cannot be re-pointed to another action's record).",
                "Action-binding: changing action_ref changes binding_ref (an action cannot claim another identity's settlement).",
                "State-binding: changing transition_hash changes binding_ref -- only the exact COMMITTED transition binds; a PENDING/REVERSED transition_hash produces a distinct binding.",
                "Chain-binding: changing retention_chain_ref changes binding_ref (the tamper-evident chain position recording the record is load-bearing).",
                "Lineage-binding: action_ref and transition_hash derive from epoch-millisecond-integer preimages (Substrate Rule 2); an RFC 3339 string timestamp upstream yields a different action_ref, hence a different binding -- a non-conformant lineage cannot reproduce the binding bytes.",
            ],
            "spec_authorship": "AlgoVoi-authored. Composes the action_ref lifecycle (action_ref_exactly_once_v1), settlement attestation (settlement_attestation_v1), and retention chain (retention_chain_v1) into a single post-settlement accountability binding. No new hashing primitive is introduced.",
        },
        "vectors": vectors,
        "pair_invariants": pair_invariants,
    }

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "settlement_action_binding_v1.json")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    print(f"wrote {len(vectors)} vectors + {len(pair_invariants)} pair invariants -> {path}")
    for v in vectors:
        print(f"  {v['vector_id']:12s} {v['pair_group']:10s} {v['expected_binding_ref']}")


if __name__ == "__main__":
    main()
