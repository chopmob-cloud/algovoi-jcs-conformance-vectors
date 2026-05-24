"""
cancellation_receipt_v1 vector set generator.

8 vectors + 6 pair invariants + 3 chain invariants.

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

OUTPUT_FILE = Path(__file__).parent / "cancellation_receipt_v1.json"

BASELINE_MANDATE_REF = (
    "sha256:0dd5d0b76c9b9281fdeb2509ad38ab132b16a17385ca01d976ff9e6e12563a0f"
)
BASELINE_PROVIDER_DID = "did:example:cancellation-provider-1"
BASELINE_RECORDED_MS = 1716494400000  # 2026-05-23 16:00:00 UTC
BASELINE_EFFECTIVE_MS = 1716537600000  # 2026-05-24 04:00:00 UTC (end-of-day-before convention)
ZERO_PREV_HASH = "0" * 64


def sha256_jcs_hex(payload: dict) -> tuple[str, str]:
    canon = canonicalize(payload)
    canon_bytes = canon.encode("utf-8") if isinstance(canon, str) else canon
    return (
        base64.b64encode(canon_bytes).decode("ascii"),
        hashlib.sha256(canon_bytes).hexdigest(),
    )


def build_receipt_vector(vector_id, description, pair_group, receipt, diff_from):
    jcs_b64, content_hash = sha256_jcs_hex(receipt)
    return {
        "vector_id": vector_id,
        "description": description,
        "pair_group": pair_group,
        "expectation": "reference",
        "receipt": receipt,
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
    v001_receipt = {
        "canon_version": "jcs-rfc8785-v1",
        "cancellation_provider_did": BASELINE_PROVIDER_DID,
        "cancellation_reason": "USER_REQUESTED",
        "cancellation_timestamp_ms": BASELINE_RECORDED_MS,
        "effective_from_ms": BASELINE_EFFECTIVE_MS,
        "jurisdiction_flags": ["UK", "EU"],
        "mandate_ref": BASELINE_MANDATE_REF,
    }
    v001 = build_receipt_vector(
        "cancellation-receipt-v1-001",
        "USER_REQUESTED cancellation (baseline). Payer revoked the mandate; "
        "effective end-of-business-day before next scheduled execution per "
        "PSD2 (Directive 2015/2366) Article 64(3)(a) for direct-debit "
        "revocation timing.",
        "reason-enum",
        v001_receipt,
        [
            "cancellation-receipt-v1-002",
            "cancellation-receipt-v1-003",
            "cancellation-receipt-v1-004",
            "cancellation-receipt-v1-005",
        ],
    )

    v002_receipt = dict(v001_receipt)
    v002_receipt["cancellation_reason"] = "MERCHANT_REQUESTED"
    v002 = build_receipt_vector(
        "cancellation-receipt-v1-002",
        "MERCHANT_REQUESTED cancellation. Payee-initiated end of recurring "
        "billing under PSD2 Article 72 and contractual terms. Does not "
        "trigger consumer-revocation refund-window obligations on "
        "already-settled debits.",
        "reason-enum",
        v002_receipt,
        ["cancellation-receipt-v1-001", "cancellation-receipt-v1-003", "cancellation-receipt-v1-004"],
    )

    v003_receipt = dict(v001_receipt)
    v003_receipt["cancellation_reason"] = "COMPLIANCE_TERMINATED"
    v003 = build_receipt_vector(
        "cancellation-receipt-v1-003",
        "COMPLIANCE_TERMINATED cancellation. Operator-forced under "
        "post-mandate compliance trigger (sanctions hit on payer, KYC "
        "failure, AML alert, court order, regulator directive). Triggers "
        "POCA s.330 / AML 5+6 audit-chain linkage back to the originating "
        "compliance event.",
        "reason-enum",
        v003_receipt,
        ["cancellation-receipt-v1-001", "cancellation-receipt-v1-002", "cancellation-receipt-v1-004"],
    )

    v004_receipt = dict(v001_receipt)
    v004_receipt["cancellation_reason"] = "EXPIRED"
    v004 = build_receipt_vector(
        "cancellation-receipt-v1-004",
        "EXPIRED cancellation. Mandate reached its agreed end-date or "
        "maximum-execution count. No party-initiated decision; the "
        "mandate's own terms terminated it. Standard record-keeping "
        "applies.",
        "reason-enum",
        v004_receipt,
        ["cancellation-receipt-v1-001", "cancellation-receipt-v1-002", "cancellation-receipt-v1-003"],
    )

    v005_receipt = dict(v001_receipt)
    v005_receipt["canon_version"] = "jcs-rfc8785-v2"
    v005 = build_receipt_vector(
        "cancellation-receipt-v1-005",
        "Canonicalisation rule pin probe. All fields identical to vector "
        "001 except canon_version is 'jcs-rfc8785-v2'. Demonstrates the "
        "in-band canonicalisation rule pin is byte-load-bearing.",
        "canon-version-pin",
        v005_receipt,
        ["cancellation-receipt-v1-001"],
    )

    v006 = build_chain_row(
        "cancellation-receipt-v1-006",
        row_number=1,
        prev_hash=ZERO_PREV_HASH,
        payload_content_hash=v001["expected_content_hash"],
        description="Audit chain row 1 anchoring the USER_REQUESTED receipt (vector 001).",
    )
    v007 = build_chain_row(
        "cancellation-receipt-v1-007",
        row_number=2,
        prev_hash=v006["expected_row_content_hash"],
        payload_content_hash=v002["expected_content_hash"],
        description="Audit chain row 2 anchoring the MERCHANT_REQUESTED receipt (vector 002).",
    )
    v008 = build_chain_row(
        "cancellation-receipt-v1-008",
        row_number=3,
        prev_hash=v007["expected_row_content_hash"],
        payload_content_hash=v003["expected_content_hash"],
        description="Audit chain row 3 anchoring the COMPLIANCE_TERMINATED receipt (vector 003).",
    )

    vectors = [v001, v002, v003, v004, v005, v006, v007, v008]

    pair_invariants = [
        {"id": "pair-cancel-001-002", "type": "different_hash_from",
         "left": "cancellation-receipt-v1-001", "right": "cancellation-receipt-v1-002",
         "rationale": "Closed enumeration byte-load-bearing: USER_REQUESTED vs MERCHANT_REQUESTED"},
        {"id": "pair-cancel-001-003", "type": "different_hash_from",
         "left": "cancellation-receipt-v1-001", "right": "cancellation-receipt-v1-003",
         "rationale": "Closed enumeration byte-load-bearing: USER_REQUESTED vs COMPLIANCE_TERMINATED"},
        {"id": "pair-cancel-001-004", "type": "different_hash_from",
         "left": "cancellation-receipt-v1-001", "right": "cancellation-receipt-v1-004",
         "rationale": "Closed enumeration byte-load-bearing: USER_REQUESTED vs EXPIRED"},
        {"id": "pair-cancel-002-003", "type": "different_hash_from",
         "left": "cancellation-receipt-v1-002", "right": "cancellation-receipt-v1-003",
         "rationale": "Closed enumeration byte-load-bearing: MERCHANT_REQUESTED vs COMPLIANCE_TERMINATED"},
        {"id": "pair-cancel-002-004", "type": "different_hash_from",
         "left": "cancellation-receipt-v1-002", "right": "cancellation-receipt-v1-004",
         "rationale": "Closed enumeration byte-load-bearing: MERCHANT_REQUESTED vs EXPIRED"},
        {"id": "pair-cancel-003-004", "type": "different_hash_from",
         "left": "cancellation-receipt-v1-003", "right": "cancellation-receipt-v1-004",
         "rationale": "Closed enumeration byte-load-bearing: COMPLIANCE_TERMINATED vs EXPIRED"},
        {"id": "pair-cancel-001-005", "type": "different_hash_from",
         "left": "cancellation-receipt-v1-001", "right": "cancellation-receipt-v1-005",
         "rationale": "canon_version pin byte-load-bearing"},
    ]

    chain_invariants = [
        {"id": "chain-cancel-001", "type": "field_equals",
         "vector": "cancellation-receipt-v1-006", "field": "row.prev_hash", "value": ZERO_PREV_HASH,
         "rationale": "Chain row 1 anchors to all-zero prev_hash"},
        {"id": "chain-cancel-002", "type": "field_equals_other",
         "left_vector": "cancellation-receipt-v1-007", "left_field": "row.prev_hash",
         "right_vector": "cancellation-receipt-v1-006", "right_field": "expected_row_content_hash",
         "rationale": "Chain row 2's prev_hash equals row 1's row_content_hash"},
        {"id": "chain-cancel-003", "type": "field_equals_other",
         "left_vector": "cancellation-receipt-v1-008", "left_field": "row.prev_hash",
         "right_vector": "cancellation-receipt-v1-007", "right_field": "expected_row_content_hash",
         "rationale": "Chain row 3's prev_hash equals row 2's row_content_hash"},
    ]

    payload = {
        "schema_version": "1.0",
        "artefact_id": "cancellation-receipt-v1-conformance",
        "published_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "canonicalizer": (
            "rfc8785@0.1.4 (Python) / canonicalize@3.0.0 (TypeScript) / "
            "gowebpki/jcs v1.0.1 (Go) / cyberphone/json-canonicalization (Java) / "
            "serde_jcs@0.2.0 (Rust) / root23/php-json-canonicalization (PHP) / "
            "Baqhub.Packages.JsonCanonicalization (.NET) / json-canonicalization (Ruby)"
        ),
        "hash": "SHA-256, lowercase hex",
        "anchored_to": {
            "ietf_id": "draft-hopley-x402-cancellation-receipt-00 (Independent Submission, Informational; AlgoVoi-authored)",
            "ietf_id_url": "https://datatracker.ietf.org/doc/draft-hopley-x402-cancellation-receipt/",
            "canonicalisation_discipline": "urn:x402:canonicalisation:jcs-rfc8785-v1 (normatively specified in draft-hopley-x402-canonicalisation-jcs-v1)",
            "load_bearing_invariants": [
                "cancellation_reason is a closed enumeration of {USER_REQUESTED, MERCHANT_REQUESTED, COMPLIANCE_TERMINATED, EXPIRED}; each value produces a byte-distinct content_hash.",
                "jurisdiction_flags is an ordered list (RFC 8785 §3.2.3).",
                "canon_version is an in-band pin; changing it produces a different content_hash.",
                "cancellation_timestamp_ms and effective_from_ms are epoch-millisecond integers (Substrate Rule 2). RFC 3339 string forms are rejected.",
                "effective_from_ms MUST be >= cancellation_timestamp_ms.",
                "mandate_ref is content-addressed (sha256:<hex>); the prefix is part of canonical bytes.",
                "Audit chain rows link via prev_hash.",
            ],
            "spec_authorship": "AlgoVoi-authored under sole authorship. Welcomes downstream-adopter contributions per Appendix C 'Known Adopters' pattern established in draft-hopley-x402-canonicalisation-jcs-v1-01.",
            "composes_with": "compliance_receipt_v1 (mandate setup), settlement_attestation_v1 (recurring execution), refund_receipt_v1 (PSD2 Art. 64 refund of revoked debits)",
        },
        "derivation": (
            "Eight cancellation-receipt-shape vectors split into two "
            "groups: (A) baseline four-state coverage of the closed "
            "enumeration (USER_REQUESTED, MERCHANT_REQUESTED, "
            "COMPLIANCE_TERMINATED, EXPIRED). The four-value enum is one "
            "wider than the three-value enums in sibling formats because "
            "the regulatorily-load-bearing distinctions in mandate "
            "termination genuinely are four-state: payer-vs-payee-vs-"
            "operator-vs-time. (B) canon_version pin probe. Three "
            "audit-chain-row vectors (006-008) demonstrate chain linkage."
        ),
        "context": {
            "substrate_packages": {
                "python": "pypi.org/project/algovoi-cancellation-receipt (>=0.1.0)",
                "typescript": "npmjs.com/package/@algovoi/cancellation-receipt (>=0.1.0)",
            },
            "primitive_modules": {
                "python": "algovoi_cancellation_receipt.build_cancellation_receipt",
                "typescript": "@algovoi/cancellation-receipt buildCancellationReceipt",
            },
            "verification_recipe": [
                "1. For each receipt vector (001 through 005), take the receipt object verbatim.",
                "2. Canonicalise under RFC 8785.",
                "3. base64-encode the JCS bytes; MUST equal expected_jcs_bytes_b64.",
                "4. SHA-256 the JCS bytes, lowercase hex; MUST equal expected_content_hash.",
                "5. For chain rows (006-008), repeat on row object; MUST equal expected_row_content_hash.",
                "6. Verify pair invariants: all seven MUST hold.",
                "7. Verify chain linkage: row 1 prev_hash zeros; rows 2, 3 link to prior row_content_hash.",
            ],
        },
        "fixed_receipt_fields": {
            "cancellation_provider_did": BASELINE_PROVIDER_DID,
            "cancellation_timestamp_ms": BASELINE_RECORDED_MS,
            "effective_from_ms": BASELINE_EFFECTIVE_MS,
            "mandate_ref": BASELINE_MANDATE_REF,
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
