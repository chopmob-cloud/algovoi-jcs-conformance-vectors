"""
settlement_attestation_v1 vector set generator.

Produces 8 byte-level reference vectors + 5 pair invariants + 3 chain
invariants for the settlement_attestation_v1 format specified in
SCHEMA.md.

The schema is the AlgoVoi-authored settlement attestation format that
composes with the compliance receipt and refund receipt formats under
the same JCS RFC 8785 canonicalisation discipline
(urn:x402:canonicalisation:jcs-rfc8785-v1, specified in
draft-hopley-x402-canonicalisation-jcs-v1-01 on the IETF datatracker).

Usage:
    pip install algovoi-substrate>=0.3.0
    python generate.py

Output: settlement_attestation_v1.json (deterministic).
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from algovoi_substrate import canonicalize

OUTPUT_FILE = Path(__file__).parent / "settlement_attestation_v1.json"

BASELINE_PAYMENT_REF = (
    "sha256:0dd5d0b76c9b9281fdeb2509ad38ab132b16a17385ca01d976ff9e6e12563a0f"
)
BASELINE_PROVIDER_DID = "did:example:settlement-provider-1"
BASELINE_TIMESTAMP_MS = 1716494400000
BASELINE_AMOUNT = {"amount_minor": "100000", "asset_id": "USDC.6"}
BASELINE_CHAIN = "ethereum:8453"  # Base mainnet by chainId
BASELINE_ROUND = 39250000  # confirmed round/block of the settling transaction
ZERO_PREV_HASH = "0" * 64


def _round_ok(value: object) -> bool:
    """settlement_round rule, reimplemented from the written contract.

    When present, ``settlement_round`` MUST be a positive integer. ``bool`` is
    an ``int`` subclass and is rejected (Substrate Rule 2). Mirrors
    substrate2.receipts._common.require_positive_int. Only the JSON-representable
    reject shapes (0, negative, boolean, string) are shipped as vectors; the
    float / wrong-type rejections are a language-binding concern covered by the
    reference implementation's unit tests (substrate2 test_settlement_round.py),
    not by a JCS vector, because RFC 8785 collapses ``39250000.0`` to the same
    number as ``39250000``.
    """
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def sha256_jcs_hex(payload: dict) -> tuple[str, str]:
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
    # -------- Vector 001: SETTLED on Base (baseline)
    v001_receipt = {
        "canon_version": "jcs-rfc8785-v1",
        "jurisdiction_flags": ["UK", "EU"],
        "settled_payment_ref": BASELINE_PAYMENT_REF,
        "settlement_amount": BASELINE_AMOUNT,
        "settlement_chain": BASELINE_CHAIN,
        "settlement_provider_did": BASELINE_PROVIDER_DID,
        "settlement_result": "SETTLED",
        "settlement_timestamp_ms": BASELINE_TIMESTAMP_MS,
    }
    v001 = build_receipt_vector(
        "settlement-attestation-v1-001",
        "Baseline SETTLED attestation on Base mainnet (ethereum:8453). Payment "
        "confirmed on-chain with sufficient finality for the operator's risk "
        "model. Triggers settlement-finality record-keeping obligations under "
        "MiCA Article 80 and AMLR Article 56. PSD2 Article 89 refund-window "
        "clock starts ticking from this point.",
        "result-enum",
        v001_receipt,
        [
            "settlement-attestation-v1-002",
            "settlement-attestation-v1-003",
            "settlement-attestation-v1-004",
            "settlement-attestation-v1-005",
        ],
    )

    # -------- Vector 002: PENDING_FINALITY (otherwise identical)
    v002_receipt = dict(v001_receipt)
    v002_receipt["settlement_result"] = "PENDING_FINALITY"
    v002 = build_receipt_vector(
        "settlement-attestation-v1-002",
        "PENDING_FINALITY attestation. All fields identical to vector 001 "
        "except settlement_result. Payment broadcast and included in a block, "
        "but awaiting the operator's required confirmation depth. Operator "
        "has visibility of inclusion but does not yet assert finality. Under "
        "PSD2 Article 89, refund-window timing differs between PENDING and "
        "SETTLED states.",
        "result-enum",
        v002_receipt,
        [
            "settlement-attestation-v1-001",
            "settlement-attestation-v1-003",
        ],
    )

    # -------- Vector 003: REVERSED
    v003_receipt = dict(v001_receipt)
    v003_receipt["settlement_result"] = "REVERSED"
    v003 = build_receipt_vector(
        "settlement-attestation-v1-003",
        "REVERSED attestation. Previously SETTLED payment now considered "
        "reversed (chain reorganisation, fraud reversal, double-spend "
        "resolution, or operator-initiated reversal under regulatory "
        "directive). Triggers reversal-evidence obligations under POCA s.330 "
        "and AML5/6, and creates a chain-of-custody record for chain-reorg "
        "adjudication.",
        "result-enum",
        v003_receipt,
        [
            "settlement-attestation-v1-001",
            "settlement-attestation-v1-002",
        ],
    )

    # -------- Vector 004: jurisdiction array-order probe
    v004_receipt = dict(v001_receipt)
    v004_receipt["jurisdiction_flags"] = ["EU", "UK"]
    v004 = build_receipt_vector(
        "settlement-attestation-v1-004",
        "Jurisdiction array-order probe. All fields identical to vector 001 "
        "except jurisdiction_flags is reordered from ['UK','EU'] to ['EU','UK']. "
        "Demonstrates that jurisdiction_flags is byte-load-bearing under "
        "RFC 8785 (arrays are not normalised during canonicalisation).",
        "jurisdiction-order",
        v004_receipt,
        ["settlement-attestation-v1-001"],
    )

    # -------- Vector 005: canon_version pin probe
    v005_receipt = dict(v001_receipt)
    v005_receipt["canon_version"] = "jcs-rfc8785-v2"
    v005 = build_receipt_vector(
        "settlement-attestation-v1-005",
        "Canonicalisation rule pin probe. All fields identical to vector 001 "
        "except canon_version is 'jcs-rfc8785-v2'. Demonstrates that the "
        "in-band canonicalisation rule pin is byte-load-bearing: an "
        "attestation emitted under one discipline version cannot be silently "
        "re-hashed under a successor rule.",
        "canon-version-pin",
        v005_receipt,
        ["settlement-attestation-v1-001"],
    )

    # -------- Audit chain rows
    v006 = build_chain_row(
        "settlement-attestation-v1-006",
        row_number=1,
        prev_hash=ZERO_PREV_HASH,
        payload_content_hash=v001["expected_content_hash"],
        description=(
            "Audit chain row 1 anchoring the SETTLED attestation (vector 001). "
            "prev_hash is 64 zero hex characters (chain anchor)."
        ),
    )
    v007 = build_chain_row(
        "settlement-attestation-v1-007",
        row_number=2,
        prev_hash=v006["expected_row_content_hash"],
        payload_content_hash=v002["expected_content_hash"],
        description=(
            "Audit chain row 2 anchoring the PENDING_FINALITY attestation "
            "(vector 002). prev_hash equals row 1's expected_row_content_hash."
        ),
    )
    v008 = build_chain_row(
        "settlement-attestation-v1-008",
        row_number=3,
        prev_hash=v007["expected_row_content_hash"],
        payload_content_hash=v003["expected_content_hash"],
        description=(
            "Audit chain row 3 anchoring the REVERSED attestation (vector 003). "
            "prev_hash equals row 2's expected_row_content_hash, completing "
            "a three-row chain a verifier can walk end-to-end."
        ),
    )

    # -------- Vector 009: SETTLED carrying settlement_round (additive field)
    # All fields identical to vector 001 plus settlement_round. Proves the
    # confirmed round/block is byte-load-bearing and sorts (RFC 8785 key order)
    # between settlement_result and settlement_timestamp_ms. This is the golden
    # vector for the round-bearing attestation: without it, enabling round
    # emission silently changes content_hash -> settlement_ref -> binding_ref
    # with nothing to byte-check against.
    v009_receipt = dict(v001_receipt)
    v009_receipt["settlement_round"] = BASELINE_ROUND
    assert _round_ok(v009_receipt["settlement_round"])
    v009 = build_receipt_vector(
        "settlement-attestation-v1-009",
        "SETTLED attestation carrying settlement_round (the confirmed "
        "round/block of the settling transaction). All fields identical to "
        "vector 001 plus settlement_round, added additively so a round-less "
        "attestation still serialises byte-for-byte as before. Under RFC 8785 "
        "key ordering settlement_round sorts between settlement_result and "
        "settlement_timestamp_ms. This binds an attestation to chain state-proof "
        "evidence (e.g. an avm-proofpack bundle) whose confirmed round MUST "
        "match this value.",
        "settlement-round",
        v009_receipt,
        ["settlement-attestation-v1-001"],
    )

    vectors = [v001, v002, v003, v004, v005, v006, v007, v008, v009]

    # -------- Reject vectors: settlement_round validity (fail-closed)
    # Each is the SETTLED baseline (vector 001 shape) with an invalid
    # settlement_round. A conformant verifier MUST refuse to emit / accept the
    # attestation before hashing. Reimplement the rule (_round_ok) from the
    # contract; do not read a published verdict back.
    def reject_vector(vid: str, bad_round: object, bad_kind: str, description: str) -> dict:
        receipt = dict(v001_receipt)
        receipt["settlement_round"] = bad_round
        assert not _round_ok(bad_round), f"{vid}: rule wrongly accepts {bad_round!r}"
        return {
            "vector_id": vid,
            "description": description,
            "expectation": "reject",
            "reject_rule": "settlement_round_positive_int",
            "bad_kind": bad_kind,
            "receipt": receipt,
        }

    settlement_round_reject_vectors = [
        reject_vector(
            "settlement-attestation-v1-r01", 0, "zero",
            "settlement_round = 0 is refused: round 0 is the genesis allocation "
            "and can never carry a settlement.",
        ),
        reject_vector(
            "settlement-attestation-v1-r02", -1, "negative",
            "settlement_round = -1 is refused: a negative round is nonsensical.",
        ),
        reject_vector(
            "settlement-attestation-v1-r03", True, "boolean",
            "settlement_round = true is refused: JSON boolean is not a round "
            "(bool is an int subclass and must be rejected, Substrate Rule 2).",
        ),
        reject_vector(
            "settlement-attestation-v1-r04", str(BASELINE_ROUND), "string",
            "settlement_round = \"39250000\" is refused: an epoch/round is an "
            "integer, not a string (RFC 3339-style string coercion is rejected).",
        ),
    ]

    pair_invariants = [
        {
            "id": "pair-settle-001-002",
            "type": "different_hash_from",
            "left": "settlement-attestation-v1-001",
            "right": "settlement-attestation-v1-002",
            "rationale": "Closed enumeration byte-load-bearing: SETTLED vs PENDING_FINALITY",
        },
        {
            "id": "pair-settle-001-003",
            "type": "different_hash_from",
            "left": "settlement-attestation-v1-001",
            "right": "settlement-attestation-v1-003",
            "rationale": "Closed enumeration byte-load-bearing: SETTLED vs REVERSED",
        },
        {
            "id": "pair-settle-002-003",
            "type": "different_hash_from",
            "left": "settlement-attestation-v1-002",
            "right": "settlement-attestation-v1-003",
            "rationale": "Closed enumeration byte-load-bearing: PENDING_FINALITY vs REVERSED",
        },
        {
            "id": "pair-settle-001-004",
            "type": "different_hash_from",
            "left": "settlement-attestation-v1-001",
            "right": "settlement-attestation-v1-004",
            "rationale": "jurisdiction_flags array-order byte-load-bearing",
        },
        {
            "id": "pair-settle-001-005",
            "type": "different_hash_from",
            "left": "settlement-attestation-v1-001",
            "right": "settlement-attestation-v1-005",
            "rationale": "canon_version pin byte-load-bearing",
        },
        {
            "id": "pair-settle-001-009",
            "type": "different_hash_from",
            "left": "settlement-attestation-v1-001",
            "right": "settlement-attestation-v1-009",
            "rationale": "settlement_round presence byte-load-bearing: a "
                         "round-bearing attestation content_hash diverges from "
                         "the round-less one, so it drives a distinct "
                         "settlement_ref / binding_ref downstream",
        },
    ]

    chain_invariants = [
        {
            "id": "chain-settle-001",
            "type": "field_equals",
            "vector": "settlement-attestation-v1-006",
            "field": "row.prev_hash",
            "value": ZERO_PREV_HASH,
            "rationale": "Chain row 1 anchors to all-zero prev_hash (genesis)",
        },
        {
            "id": "chain-settle-002",
            "type": "field_equals_other",
            "left_vector": "settlement-attestation-v1-007",
            "left_field": "row.prev_hash",
            "right_vector": "settlement-attestation-v1-006",
            "right_field": "expected_row_content_hash",
            "rationale": "Chain row 2's prev_hash equals row 1's row_content_hash",
        },
        {
            "id": "chain-settle-003",
            "type": "field_equals_other",
            "left_vector": "settlement-attestation-v1-008",
            "left_field": "row.prev_hash",
            "right_vector": "settlement-attestation-v1-007",
            "right_field": "expected_row_content_hash",
            "rationale": "Chain row 3's prev_hash equals row 2's row_content_hash",
        },
    ]

    payload = {
        "schema_version": "1.0",
        "artefact_id": "settlement-attestation-v1-conformance",
        # Fixed (not clock-derived) so the set regenerates byte-for-byte; the
        # timestamp is provenance metadata, not part of any hashed preimage.
        "published_at": "2026-08-02T00:00:00Z",
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
                "draft-hopley-x402-settlement-attestation-00 (Independent "
                "Submission, Informational; AlgoVoi-authored)"
            ),
            "ietf_id_url": (
                "https://datatracker.ietf.org/doc/draft-hopley-x402-settlement-attestation/"
            ),
            "canonicalisation_discipline": (
                "urn:x402:canonicalisation:jcs-rfc8785-v1 (normatively "
                "specified in draft-hopley-x402-canonicalisation-jcs-v1)"
            ),
            "load_bearing_invariants": [
                "settlement_result is a closed enumeration of {SETTLED, "
                "PENDING_FINALITY, REVERSED}; each value produces a "
                "byte-distinct content_hash from the other two.",
                "jurisdiction_flags is an ordered list; reordering the "
                "array elements produces a different content_hash.",
                "canon_version is an in-band pin; changing the pin value "
                "produces a different content_hash.",
                "settlement_timestamp_ms is an epoch-millisecond integer "
                "(Substrate Rule 2). RFC 3339 string forms are rejected.",
                "settlement_amount is a sub-object {amount_minor: string, "
                "asset_id: string}; JCS sorts the sub-object's keys "
                "lexicographically.",
                "settlement_chain is a flat string identifier "
                "(<chain_family> or <chain_family>:<network>); JCS "
                "canonicalises the string as opaque bytes without "
                "decomposition.",
                "Audit chain rows link via prev_hash. Row N's prev_hash "
                "MUST equal row N-1's row_content_hash; row 1's prev_hash "
                "MUST be 64 zero hex characters.",
                "settlement_round is an additive optional field (the confirmed "
                "round/block of the settling transaction). Present, it is a "
                "positive integer emitted as its own key and sorts between "
                "settlement_result and settlement_timestamp_ms; absent, the "
                "body serialises byte-for-byte as before the field existed. "
                "A settlement_round of 0, a negative round, a boolean, or a "
                "string is refused before the attestation is emitted.",
            ],
            "spec_authorship": (
                "AlgoVoi-authored. The receipt format and canonicalisation "
                "discipline are specified in "
                "draft-hopley-x402-settlement-attestation-00 (companion to "
                "the compliance receipt and refund receipt I-Ds)."
            ),
            "composes_with": (
                "compliance_receipt_v1 (via settled_payment_ref linkage); "
                "refund_receipt_v1 (a refund receipt's original_payment_ref "
                "MAY equal a settlement attestation content_hash)"
            ),
        },
        "derivation": (
            "Eight settlement-attestation-shape vectors split into three "
            "groups: (A) baseline three-state coverage of the closed "
            "enumeration (SETTLED, PENDING_FINALITY, REVERSED), proving the "
            "settlement_result field is byte-load-bearing -- regulatorily "
            "load-bearing for settlement-finality record-keeping (MiCA Art. "
            "80, AMLR Art. 56) and PSD2 Article 89 refund-window timing; "
            "(B) jurisdiction array-order probe; (C) canon_version pin "
            "probe. Three audit-chain-row vectors (006-008) demonstrate "
            "chain linkage."
        ),
        "context": {
            "substrate_packages": {
                "python": "pypi.org/project/algovoi-settlement-attestation (>=0.1.0)",
                "typescript": "npmjs.com/package/@algovoi/settlement-attestation (>=0.1.0)",
            },
            "primitive_modules": {
                "python": (
                    "algovoi_settlement_attestation.build_settlement_attestation"
                ),
                "typescript": (
                    "@algovoi/settlement-attestation buildSettlementAttestation"
                ),
            },
            "verification_recipe": [
                "1. For each receipt vector (001 through 005), take the "
                "receipt object verbatim.",
                "2. Canonicalise under RFC 8785.",
                "3. base64-encode the JCS bytes; MUST equal "
                "expected_jcs_bytes_b64.",
                "4. SHA-256 the JCS bytes, lowercase hex; MUST equal "
                "expected_content_hash.",
                "5. For chain rows (006 through 008), repeat steps 2-4 on "
                "the row object; result MUST equal expected_row_content_hash.",
                "6. Verify pair invariants: all five MUST hold "
                "(different_hash_from).",
                "7. Verify chain linkage: row 1 prev_hash is 64 zeros; "
                "row 2 prev_hash equals row 1 row_content_hash; row 3 "
                "prev_hash equals row 2 row_content_hash.",
            ],
        },
        "fixed_receipt_fields": {
            "settled_payment_ref": BASELINE_PAYMENT_REF,
            "settlement_amount": BASELINE_AMOUNT,
            "settlement_chain": BASELINE_CHAIN,
            "settlement_provider_did": BASELINE_PROVIDER_DID,
            "settlement_timestamp_ms": BASELINE_TIMESTAMP_MS,
        },
        "vectors": vectors,
        "pair_invariants": pair_invariants,
        "chain_invariants": chain_invariants,
        "settlement_round_reject_vectors": settlement_round_reject_vectors,
    }

    OUTPUT_FILE.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"wrote {OUTPUT_FILE.name}")
    print(
        f"  {len(vectors)} vectors + {len(pair_invariants)} pair invariants + "
        f"{len(chain_invariants)} chain invariants + "
        f"{len(settlement_round_reject_vectors)} settlement_round reject vectors"
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
