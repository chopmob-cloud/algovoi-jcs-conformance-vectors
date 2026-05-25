"""
composite_trust_query_v1 vector set generator.

8 vectors + 7 pair invariants + 3 chain invariants.

Usage:
    pip install algovoi-substrate>=0.3.0
    python generate.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from algovoi_substrate import canonicalize

OUTPUT_FILE = Path(__file__).parent / "composite_trust_query_v1.json"

BASELINE_CHAIN_REF = (
    "sha256:0dd5d0b76c9b9281fdeb2509ad38ab132b16a17385ca01d976ff9e6e12563a0f"
)
BASELINE_QUERY_REF = (
    "sha256:8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52"
)
BASELINE_VERIFIER_DID = "did:example:trust-verifier-1"
BASELINE_TIMESTAMP_MS = 1716494400000  # 2026-05-23 16:00:00 UTC
ZERO_PREV_HASH = "0" * 64


def sha256_jcs_hex(payload: dict) -> tuple[str, str]:
    canon = canonicalize(payload)
    canon_bytes = canon.encode("utf-8") if isinstance(canon, str) else canon
    return (
        base64.b64encode(canon_bytes).decode("ascii"),
        hashlib.sha256(canon_bytes).hexdigest(),
    )


def build_response_vector(vector_id, description, pair_group, response, diff_from):
    jcs_b64, content_hash = sha256_jcs_hex(response)
    return {
        "vector_id": vector_id,
        "description": description,
        "pair_group": pair_group,
        "expectation": "reference",
        "response": response,
        "expected_jcs_bytes_b64": jcs_b64,
        "expected_content_hash": content_hash,
        "different_hash_from": diff_from,
    }


def build_chain_row(vector_id, row_number, prev_hash, payload_content_hash, description):
    row = {
        "content_hash": payload_content_hash,
        "prev_hash": prev_hash,
        "row_number": row_number,
    }
    jcs_b64, row_content_hash = sha256_jcs_hex(row)
    return {
        "vector_id": vector_id,
        "description": description,
        "pair_group": "audit-chain",
        "expectation": "reference",
        "row": row,
        "expected_jcs_bytes_b64": jcs_b64,
        "expected_row_content_hash": row_content_hash,
    }


def main() -> int:
    v001_response = {
        "canon_version": "jcs-rfc8785-v1",
        "chain_ref": BASELINE_CHAIN_REF,
        "ctq_timestamp_ms": BASELINE_TIMESTAMP_MS,
        "jurisdiction_flags": ["UK", "EU"],
        "query_ref": BASELINE_QUERY_REF,
        "trust_outcome": "TRUSTED",
        "verifier_did": BASELINE_VERIFIER_DID,
    }
    v001 = build_response_vector(
        "composite-trust-query-v1-001",
        "TRUSTED outcome (baseline). Verifier walked the audit chain, all "
        "anchored receipts present and consistent under the asserted "
        "jurisdiction(s). No revocation, reversal, or compliance-forced "
        "termination on the chain. Operator may proceed.",
        "outcome-enum",
        v001_response,
        [
            "composite-trust-query-v1-002",
            "composite-trust-query-v1-003",
            "composite-trust-query-v1-004",
            "composite-trust-query-v1-005",
        ],
    )

    v002_response = dict(v001_response)
    v002_response["trust_outcome"] = "PROVISIONAL"
    v002 = build_response_vector(
        "composite-trust-query-v1-002",
        "PROVISIONAL outcome. Some receipts in the chain are in "
        "PENDING_FINALITY or analogous non-terminal state; verifier can "
        "affirm partial state but not full settlement. Operator should "
        "proceed cautiously and re-query after pending events finalise.",
        "outcome-enum",
        v002_response,
        [
            "composite-trust-query-v1-001",
            "composite-trust-query-v1-003",
            "composite-trust-query-v1-004",
        ],
    )

    v003_response = dict(v001_response)
    v003_response["trust_outcome"] = "INSUFFICIENT_EVIDENCE"
    v003 = build_response_vector(
        "composite-trust-query-v1-003",
        "INSUFFICIENT_EVIDENCE outcome. Chain does not contain enough "
        "evidence to answer the query: chain segments missing, query "
        "references state outside the chain, or content-addressed "
        "pointers undereferenceable. Operator should gather more "
        "evidence; do not proceed under TRUSTED.",
        "outcome-enum",
        v003_response,
        [
            "composite-trust-query-v1-001",
            "composite-trust-query-v1-002",
            "composite-trust-query-v1-004",
        ],
    )

    v004_response = dict(v001_response)
    v004_response["trust_outcome"] = "UNTRUSTED"
    v004 = build_response_vector(
        "composite-trust-query-v1-004",
        "UNTRUSTED outcome. Chain contains evidence that negates the "
        "query (compliance-forced termination, settled-then-reversed "
        "transaction, REJECTED refund, expired mandate). Operator "
        "should halt the action the query was framed to authorise.",
        "outcome-enum",
        v004_response,
        [
            "composite-trust-query-v1-001",
            "composite-trust-query-v1-002",
            "composite-trust-query-v1-003",
        ],
    )

    v005_response = dict(v001_response)
    v005_response["canon_version"] = "jcs-rfc8785-v2"
    v005 = build_response_vector(
        "composite-trust-query-v1-005",
        "Canonicalisation rule pin probe. All fields identical to vector "
        "001 except canon_version is 'jcs-rfc8785-v2'. Demonstrates the "
        "in-band canonicalisation rule pin is byte-load-bearing.",
        "canon-version-pin",
        v005_response,
        ["composite-trust-query-v1-001"],
    )

    v006 = build_chain_row(
        "composite-trust-query-v1-006",
        row_number=1,
        prev_hash=ZERO_PREV_HASH,
        payload_content_hash=v001["expected_content_hash"],
        description="Audit chain row 1 anchoring the TRUSTED response (vector 001).",
    )
    v007 = build_chain_row(
        "composite-trust-query-v1-007",
        row_number=2,
        prev_hash=v006["expected_row_content_hash"],
        payload_content_hash=v002["expected_content_hash"],
        description="Audit chain row 2 anchoring the PROVISIONAL response (vector 002).",
    )
    v008 = build_chain_row(
        "composite-trust-query-v1-008",
        row_number=3,
        prev_hash=v007["expected_row_content_hash"],
        payload_content_hash=v004["expected_content_hash"],
        description="Audit chain row 3 anchoring the UNTRUSTED response (vector 004).",
    )

    vectors = [v001, v002, v003, v004, v005, v006, v007, v008]

    pair_invariants = [
        {"id": "pair-ctq-001-002", "type": "different_hash_from",
         "left": "composite-trust-query-v1-001", "right": "composite-trust-query-v1-002",
         "rationale": "Closed enumeration byte-load-bearing: TRUSTED vs PROVISIONAL"},
        {"id": "pair-ctq-001-003", "type": "different_hash_from",
         "left": "composite-trust-query-v1-001", "right": "composite-trust-query-v1-003",
         "rationale": "Closed enumeration byte-load-bearing: TRUSTED vs INSUFFICIENT_EVIDENCE"},
        {"id": "pair-ctq-001-004", "type": "different_hash_from",
         "left": "composite-trust-query-v1-001", "right": "composite-trust-query-v1-004",
         "rationale": "Closed enumeration byte-load-bearing: TRUSTED vs UNTRUSTED"},
        {"id": "pair-ctq-002-003", "type": "different_hash_from",
         "left": "composite-trust-query-v1-002", "right": "composite-trust-query-v1-003",
         "rationale": "Closed enumeration byte-load-bearing: PROVISIONAL vs INSUFFICIENT_EVIDENCE"},
        {"id": "pair-ctq-002-004", "type": "different_hash_from",
         "left": "composite-trust-query-v1-002", "right": "composite-trust-query-v1-004",
         "rationale": "Closed enumeration byte-load-bearing: PROVISIONAL vs UNTRUSTED"},
        {"id": "pair-ctq-003-004", "type": "different_hash_from",
         "left": "composite-trust-query-v1-003", "right": "composite-trust-query-v1-004",
         "rationale": "Closed enumeration byte-load-bearing: INSUFFICIENT_EVIDENCE vs UNTRUSTED"},
        {"id": "pair-ctq-001-005", "type": "different_hash_from",
         "left": "composite-trust-query-v1-001", "right": "composite-trust-query-v1-005",
         "rationale": "canon_version pin byte-load-bearing"},
    ]

    chain_invariants = [
        {"id": "chain-ctq-001", "type": "field_equals",
         "vector": "composite-trust-query-v1-006", "field": "row.prev_hash", "value": ZERO_PREV_HASH,
         "rationale": "Chain row 1 anchors to all-zero prev_hash"},
        {"id": "chain-ctq-002", "type": "field_equals_other",
         "left_vector": "composite-trust-query-v1-007", "left_field": "row.prev_hash",
         "right_vector": "composite-trust-query-v1-006", "right_field": "expected_row_content_hash",
         "rationale": "Chain row 2's prev_hash equals row 1's row_content_hash"},
        {"id": "chain-ctq-003", "type": "field_equals_other",
         "left_vector": "composite-trust-query-v1-008", "left_field": "row.prev_hash",
         "right_vector": "composite-trust-query-v1-007", "right_field": "expected_row_content_hash",
         "rationale": "Chain row 3's prev_hash equals row 2's row_content_hash"},
    ]

    payload = {
        "schema_version": "1.0",
        "artefact_id": "composite-trust-query-v1-conformance",
        "published_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "canonicalizer": (
            "rfc8785@0.1.4 (Python) / canonicalize@3.0.0 (TypeScript) / "
            "gowebpki/jcs v1.0.1 (Go) / cyberphone/json-canonicalization (Java) / "
            "serde_jcs@0.2.0 (Rust) / root23/php-json-canonicalization (PHP) / "
            "Baqhub.Packages.JsonCanonicalization (.NET) / json-canonicalization (Ruby)"
        ),
        "hash": "SHA-256, lowercase hex",
        "anchored_to": {
            "ietf_id": "draft-hopley-x402-composite-trust-query-00 (Independent Submission, Informational; AlgoVoi-authored)",
            "ietf_id_url": "https://datatracker.ietf.org/doc/draft-hopley-x402-composite-trust-query/",
            "canonicalisation_discipline": "urn:x402:canonicalisation:jcs-rfc8785-v1 (normatively specified in draft-hopley-x402-canonicalisation-jcs-v1)",
            "load_bearing_invariants": [
                "trust_outcome is a closed enumeration of {TRUSTED, PROVISIONAL, INSUFFICIENT_EVIDENCE, UNTRUSTED}; each value produces a byte-distinct content_hash.",
                "jurisdiction_flags is an ordered list (RFC 8785 §3.2.3).",
                "canon_version is an in-band pin; changing it produces a different content_hash.",
                "ctq_timestamp_ms is an epoch-millisecond integer (Substrate Rule 2). RFC 3339 string forms are rejected.",
                "chain_ref and query_ref are content-addressed (sha256:<hex>); prefix is part of canonical bytes.",
                "Audit chain rows link via prev_hash.",
            ],
            "spec_authorship": "AlgoVoi-authored. Welcomes downstream-adopter contributions per Appendix C 'Known Adopters' pattern established in draft-hopley-x402-canonicalisation-jcs-v1-01.",
            "composes_with": "compliance_receipt_v1 (admission), settlement_attestation_v1 (settlement), cancellation_receipt_v1 (mandate termination), refund_receipt_v1 (refund). The CTQ response sits above the four receipt formats and references an audit chain composed of them via chain_ref.",
        },
        "derivation": (
            "Eight composite-trust-query-shape vectors split into two "
            "groups: (A) baseline four-state coverage of the closed "
            "enumeration (TRUSTED, PROVISIONAL, INSUFFICIENT_EVIDENCE, "
            "UNTRUSTED). The four-value enum captures a genuinely "
            "four-state decision space: proceed, proceed-with-caution, "
            "hold-pending-more-data, halt. Collapsing to three values "
            "loses the operationally-distinct INSUFFICIENT_EVIDENCE "
            "state. (B) canon_version pin probe. Three audit-chain-row "
            "vectors (006-008) demonstrate chain linkage when a CTQ "
            "response is itself embedded in an audit chain."
        ),
        "context": {
            "substrate_packages": {
                "python": "pypi.org/project/algovoi-composite-trust-query (>=0.1.0)",
                "typescript": "npmjs.com/package/@algovoi/composite-trust-query (>=0.1.0)",
            },
            "primitive_modules": {
                "python": "algovoi_composite_trust_query.build_ctq_response",
                "typescript": "@algovoi/composite-trust-query buildCtqResponse",
            },
            "verification_recipe": [
                "1. For each response vector (001 through 005), take the response object verbatim.",
                "2. Canonicalise under RFC 8785.",
                "3. base64-encode the JCS bytes; MUST equal expected_jcs_bytes_b64.",
                "4. SHA-256 the JCS bytes, lowercase hex; MUST equal expected_content_hash.",
                "5. For chain rows (006-008), repeat on row object; MUST equal expected_row_content_hash.",
                "6. Verify pair invariants: all seven MUST hold.",
                "7. Verify chain linkage: row 1 prev_hash zeros; rows 2, 3 link to prior row_content_hash.",
            ],
        },
        "fixed_response_fields": {
            "chain_ref": BASELINE_CHAIN_REF,
            "ctq_timestamp_ms": BASELINE_TIMESTAMP_MS,
            "query_ref": BASELINE_QUERY_REF,
            "verifier_did": BASELINE_VERIFIER_DID,
        },
        "vectors": vectors,
        "pair_invariants": pair_invariants,
        "chain_invariants": chain_invariants,
    }

    OUTPUT_FILE.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {OUTPUT_FILE.name}")
    print(
        f"  {len(vectors)} vectors + {len(pair_invariants)} pair invariants + "
        f"{len(chain_invariants)} chain invariants"
    )
    print()
    print("vector content_hashes:")
    for v in vectors:
        h = v.get("expected_content_hash") or v.get("expected_row_content_hash")
        print(f"  {v['vector_id']}: {h}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
