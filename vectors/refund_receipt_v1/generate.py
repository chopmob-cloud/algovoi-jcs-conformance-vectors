"""
refund_receipt_v1 vector set generator.

Produces 8 byte-level reference vectors + 5 pair invariants + 3 chain
invariants for the refund_receipt_v1 format specified in SCHEMA.md.

The schema is the AlgoVoi-authored refund receipt format that composes
with the compliance receipt format pinned in
draft-hopley-x402-compliance-receipt-00 under the same JCS RFC 8785
canonicalisation discipline (urn:x402:canonicalisation:jcs-rfc8785-v1).

Usage:
    pip install algovoi-substrate>=0.3.0
    python generate.py

Output: refund_receipt_v1.json (overwrites in place; deterministic).
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from algovoi_substrate import canonicalize

OUTPUT_FILE = Path(__file__).parent / "refund_receipt_v1.json"

# Fixed baseline receipt fields, shared across vectors 001-005.
BASELINE_PAYMENT_REF = (
    "sha256:0dd5d0b76c9b9281fdeb2509ad38ab132b16a17385ca01d976ff9e6e12563a0f"
)
BASELINE_PROVIDER_DID = "did:example:refund-provider-1"
BASELINE_TIMESTAMP_MS = 1716494400000
BASELINE_AMOUNT = {"amount_minor": "100000", "asset_id": "USDC.6"}
ZERO_PREV_HASH = "0" * 64


def sha256_jcs_hex(payload: dict) -> tuple[str, str]:
    """Return (jcs_bytes_b64, sha256_hex) for the canonicalised payload."""
    canon = canonicalize(payload)
    canon_bytes = canon.encode("utf-8") if isinstance(canon, str) else canon
    jcs_b64 = base64.b64encode(canon_bytes).decode("ascii")
    digest = hashlib.sha256(canon_bytes).hexdigest()
    return jcs_b64, digest


def build_receipt_vector(
    vector_id: str,
    description: str,
    pair_group: str,
    receipt: dict,
    different_hash_from: list[str],
) -> dict:
    jcs_b64, content_hash = sha256_jcs_hex(receipt)
    return {
        "vector_id": vector_id,
        "description": description,
        "pair_group": pair_group,
        "expectation": "reference",
        "receipt": receipt,
        "expected_jcs_bytes_b64": jcs_b64,
        "expected_content_hash": content_hash,
        "different_hash_from": different_hash_from,
    }


def build_chain_row(
    vector_id: str,
    row_number: int,
    prev_hash: str,
    payload_content_hash: str,
    description: str,
) -> dict:
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
    # -------- Vector 001: FULL refund (baseline)
    v001_receipt = {
        "canon_version": "jcs-rfc8785-v1",
        "jurisdiction_flags": ["UK", "EU"],
        "original_payment_ref": BASELINE_PAYMENT_REF,
        "refund_amount": BASELINE_AMOUNT,
        "refund_provider_did": BASELINE_PROVIDER_DID,
        "refund_result": "FULL",
        "refund_timestamp_ms": BASELINE_TIMESTAMP_MS,
    }
    v001 = build_receipt_vector(
        "refund-receipt-v1-001",
        "Baseline FULL refund receipt. The original payment amount has been "
        "returned to the payer. Closes the original payment under UK Consumer "
        "Rights Act 2015 and EU Consumer Rights Directive 2011/83/EU Article 9.",
        "result-enum",
        v001_receipt,
        [
            "refund-receipt-v1-002",
            "refund-receipt-v1-003",
            "refund-receipt-v1-004",
            "refund-receipt-v1-005",
        ],
    )

    # -------- Vector 002: PARTIAL refund (same fields except result)
    v002_receipt = dict(v001_receipt)
    v002_receipt["refund_result"] = "PARTIAL"
    v002 = build_receipt_vector(
        "refund-receipt-v1-002",
        "PARTIAL refund receipt. All fields identical to vector 001 except "
        "refund_result is PARTIAL. Does not close the original payment under "
        "consumer-rights statutes; the receipt records that some-but-not-all of "
        "the original amount has been returned and further obligations may "
        "remain. The actual refunded value is in refund_amount.",
        "result-enum",
        v002_receipt,
        [
            "refund-receipt-v1-001",
            "refund-receipt-v1-003",
        ],
    )

    # -------- Vector 003: REJECTED refund
    v003_receipt = dict(v001_receipt)
    v003_receipt["refund_result"] = "REJECTED"
    v003 = build_receipt_vector(
        "refund-receipt-v1-003",
        "REJECTED refund receipt. All fields identical to vector 001 except "
        "refund_result is REJECTED. No funds moved; the receipt records the "
        "denial event so downstream dispute/chargeback chains can reference it. "
        "Required under PSD2 (Directive 2015/2366) Article 89 for unauthorised-"
        "payment refund disputes: a payer denied a refund must receive a "
        "documented denial.",
        "result-enum",
        v003_receipt,
        [
            "refund-receipt-v1-001",
            "refund-receipt-v1-002",
        ],
    )

    # -------- Vector 004: jurisdiction array-order probe
    v004_receipt = dict(v001_receipt)
    v004_receipt["jurisdiction_flags"] = ["EU", "UK"]
    v004 = build_receipt_vector(
        "refund-receipt-v1-004",
        "Jurisdiction array-order probe. All fields identical to vector 001 "
        "except jurisdiction_flags is reordered from ['UK','EU'] to ['EU','UK']. "
        "Demonstrates that jurisdiction_flags is byte-load-bearing under RFC 8785 "
        "(arrays are not normalised during canonicalisation per RFC 8785 §3.2.3).",
        "jurisdiction-order",
        v004_receipt,
        ["refund-receipt-v1-001"],
    )

    # -------- Vector 005: canon_version pin probe
    v005_receipt = dict(v001_receipt)
    v005_receipt["canon_version"] = "jcs-rfc8785-v2"
    v005 = build_receipt_vector(
        "refund-receipt-v1-005",
        "Canonicalisation rule pin probe. All fields identical to vector 001 "
        "except canon_version is 'jcs-rfc8785-v2' rather than 'jcs-rfc8785-v1'. "
        "Demonstrates that the in-band canonicalisation rule pin is byte-load-"
        "bearing: a receipt emitted under one canonicalisation discipline "
        "version cannot be silently re-hashed under a successor rule.",
        "canon-version-pin",
        v005_receipt,
        ["refund-receipt-v1-001"],
    )

    # -------- Vectors 006-008: audit chain rows
    v006 = build_chain_row(
        "refund-receipt-v1-006",
        row_number=1,
        prev_hash=ZERO_PREV_HASH,
        payload_content_hash=v001["expected_content_hash"],
        description=(
            "Audit chain row 1 anchoring the FULL refund receipt (vector 001). "
            "prev_hash is 64 zero hex characters (chain anchor); content_hash "
            "is the canonical content_hash of vector 001."
        ),
    )
    v007 = build_chain_row(
        "refund-receipt-v1-007",
        row_number=2,
        prev_hash=v006["expected_row_content_hash"],
        payload_content_hash=v002["expected_content_hash"],
        description=(
            "Audit chain row 2 anchoring the PARTIAL refund receipt (vector 002). "
            "prev_hash equals row 1's expected_row_content_hash, linking the "
            "PARTIAL event to the FULL event in the chain."
        ),
    )
    v008 = build_chain_row(
        "refund-receipt-v1-008",
        row_number=3,
        prev_hash=v007["expected_row_content_hash"],
        payload_content_hash=v003["expected_content_hash"],
        description=(
            "Audit chain row 3 anchoring the REJECTED refund receipt (vector 003). "
            "prev_hash equals row 2's expected_row_content_hash, completing a "
            "three-row chain that a verifier can walk end-to-end."
        ),
    )

    vectors = [v001, v002, v003, v004, v005, v006, v007, v008]

    # -------- Pair invariants (5)
    pair_invariants = [
        {
            "id": "pair-refund-001-002",
            "type": "different_hash_from",
            "left": "refund-receipt-v1-001",
            "right": "refund-receipt-v1-002",
            "rationale": "Closed enumeration byte-load-bearing: FULL vs PARTIAL",
        },
        {
            "id": "pair-refund-001-003",
            "type": "different_hash_from",
            "left": "refund-receipt-v1-001",
            "right": "refund-receipt-v1-003",
            "rationale": "Closed enumeration byte-load-bearing: FULL vs REJECTED",
        },
        {
            "id": "pair-refund-002-003",
            "type": "different_hash_from",
            "left": "refund-receipt-v1-002",
            "right": "refund-receipt-v1-003",
            "rationale": "Closed enumeration byte-load-bearing: PARTIAL vs REJECTED",
        },
        {
            "id": "pair-refund-001-004",
            "type": "different_hash_from",
            "left": "refund-receipt-v1-001",
            "right": "refund-receipt-v1-004",
            "rationale": (
                "jurisdiction_flags array order byte-load-bearing: "
                "['UK','EU'] vs ['EU','UK']"
            ),
        },
        {
            "id": "pair-refund-001-005",
            "type": "different_hash_from",
            "left": "refund-receipt-v1-001",
            "right": "refund-receipt-v1-005",
            "rationale": (
                "canon_version pin byte-load-bearing: jcs-rfc8785-v1 vs "
                "jcs-rfc8785-v2"
            ),
        },
    ]

    # -------- Chain invariants (3)
    chain_invariants = [
        {
            "id": "chain-refund-001",
            "type": "field_equals",
            "vector": "refund-receipt-v1-006",
            "field": "row.prev_hash",
            "value": ZERO_PREV_HASH,
            "rationale": (
                "Chain row 1 anchors to all-zero prev_hash (chain genesis)"
            ),
        },
        {
            "id": "chain-refund-002",
            "type": "field_equals_other",
            "left_vector": "refund-receipt-v1-007",
            "left_field": "row.prev_hash",
            "right_vector": "refund-receipt-v1-006",
            "right_field": "expected_row_content_hash",
            "rationale": (
                "Chain row 2's prev_hash equals row 1's row_content_hash"
            ),
        },
        {
            "id": "chain-refund-003",
            "type": "field_equals_other",
            "left_vector": "refund-receipt-v1-008",
            "left_field": "row.prev_hash",
            "right_vector": "refund-receipt-v1-007",
            "right_field": "expected_row_content_hash",
            "rationale": (
                "Chain row 3's prev_hash equals row 2's row_content_hash"
            ),
        },
    ]

    payload = {
        "schema_version": "1.0",
        "artefact_id": "refund-receipt-v1-conformance",
        "published_at": "2026-05-24T07:57:58Z",  # frozen (was clock-derived) so the set regenerates byte-for-byte
        "canonicalizer": (
            "rfc8785@0.1.4 (Python) / canonicalize@3.0.0 (TypeScript) / "
            "gowebpki/jcs v1.0.1 (Go) / cyberphone/json-canonicalization (Java) / "
            "serde_jcs@0.2.0 (Rust) / root23/php-json-canonicalization (PHP) / "
            "Baqhub.Packages.JsonCanonicalization (.NET) / "
            "json-canonicalization (Ruby)"
        ),
        "hash": "SHA-256, lowercase hex",
        "anchored_to": {
            "ietf_id": (
                "draft-hopley-x402-refund-receipt-00 (Independent Submission, "
                "Informational; AlgoVoi-authored companion to "
                "draft-hopley-x402-compliance-receipt-00)"
            ),
            "ietf_id_url": (
                "https://datatracker.ietf.org/doc/draft-hopley-x402-refund-receipt/"
            ),
            "canonicalisation_discipline": (
                "urn:x402:canonicalisation:jcs-rfc8785-v1"
            ),
            "load_bearing_invariants": [
                "refund_result is a closed enumeration of {FULL, PARTIAL, "
                "REJECTED}; each value produces a byte-distinct content_hash "
                "from the other two.",
                "jurisdiction_flags is an ordered list; reordering the array "
                "elements produces a different content_hash (arrays are "
                "byte-load-bearing under RFC 8785).",
                "canon_version is an in-band pin; changing the pin value "
                "produces a different content_hash.",
                "refund_timestamp_ms is an epoch-millisecond integer "
                "(Substrate Rule 2). RFC 3339 string forms are rejected at "
                "validation time by the substrate's build_refund_receipt "
                "primitive.",
                "refund_amount is a sub-object {amount_minor: string, "
                "asset_id: string}; JCS sorts the sub-object's keys "
                "lexicographically.",
                "Audit chain rows link via prev_hash. Row N's prev_hash MUST "
                "equal row N-1's row_content_hash; row 1's prev_hash MUST be "
                "64 zero hex characters.",
            ],
            "spec_authorship": (
                "AlgoVoi-authored. The receipt format and canonicalisation "
                "discipline are specified in "
                "draft-hopley-x402-refund-receipt-00 (companion to the "
                "compliance receipt I-D)."
            ),
            "composes_with": (
                "compliance_receipt_v1 (via original_payment_ref linkage)"
            ),
        },
        "derivation": (
            "Eight refund-receipt-shape vectors split into three groups: "
            "(A) baseline three-state coverage of the closed enumeration "
            "(FULL, PARTIAL, REJECTED) with otherwise identical fields, "
            "proving the refund_result field is byte-load-bearing -- this "
            "is the load-bearing property under consumer-rights and PSD2 "
            "statutes where a REJECTED outcome carries dispute-evidence "
            "obligations distinct from FULL/PARTIAL; (B) array-order probe "
            "demonstrating that jurisdiction_flags is byte-load-bearing "
            "under RFC 8785; (C) canon_version pin probe demonstrating "
            "that the in-band canonicalisation rule pin is byte-load-bearing. "
            "Three additional audit-chain-row vectors (006-008) demonstrate "
            "the chain linkage property: each row's prev_hash equals the "
            "previous row's row_content_hash, with row 1 anchoring to all-zero."
        ),
        "context": {
            "substrate_packages": {
                "python": "pypi.org/project/algovoi-substrate (>=0.4.0)",
                "typescript": "npmjs.com/package/@algovoi/substrate (>=0.4.0)",
            },
            "primitive_modules": {
                "python": (
                    "algovoi_substrate.refund_receipt.build_refund_receipt "
                    "+ algovoi_substrate.canonicalize.sha256_jcs"
                ),
                "typescript": (
                    "@algovoi/substrate buildRefundReceipt + sha256Jcs"
                ),
            },
            "verification_recipe": [
                "1. For each receipt vector (001 through 005), take the "
                "receipt object verbatim.",
                "2. Canonicalise under RFC 8785 (any of the eight reference "
                "impls).",
                "3. base64-encode the JCS bytes; MUST equal "
                "expected_jcs_bytes_b64.",
                "4. SHA-256 the JCS bytes, lowercase hex; MUST equal "
                "expected_content_hash.",
                "5. For chain rows (006 through 008), repeat steps 2-4 on the "
                "row object; the result MUST equal expected_row_content_hash.",
                "6. Verify pair invariants: all five MUST hold "
                "(different_hash_from).",
                "7. Verify chain linkage: row 1 prev_hash is 64 zeros; row 2 "
                "prev_hash equals row 1 row_content_hash; row 3 prev_hash "
                "equals row 2 row_content_hash.",
            ],
        },
        "fixed_receipt_fields": {
            "original_payment_ref": BASELINE_PAYMENT_REF,
            "refund_amount": BASELINE_AMOUNT,
            "refund_provider_did": BASELINE_PROVIDER_DID,
            "refund_timestamp_ms": BASELINE_TIMESTAMP_MS,
        },
        "vectors": vectors,
        "pair_invariants": pair_invariants,
        "chain_invariants": chain_invariants,
    }

    OUTPUT_FILE.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"wrote {OUTPUT_FILE.name}")
    print(
        f"  {len(vectors)} vectors + {len(pair_invariants)} pair invariants + "
        f"{len(chain_invariants)} chain invariants"
    )
    print()
    print("vector content_hashes:")
    for v in vectors:
        if "expected_content_hash" in v:
            print(f"  {v['vector_id']}: {v['expected_content_hash']}")
        else:
            print(
                f"  {v['vector_id']}: {v['expected_row_content_hash']} "
                f"(row, prev={v['row']['prev_hash'][:16]}...)"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
