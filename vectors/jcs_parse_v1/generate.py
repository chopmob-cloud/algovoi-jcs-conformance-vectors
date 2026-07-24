#!/usr/bin/env python3
"""Generate jcs_parse_v1: parse-layer preconditions for RFC 8785 canonicalisation.

RFC 8785 canonicalises an ALREADY-PARSED JSON value. Duplicate object members
therefore cannot be expressed in any vector set whose input is a parsed value:
the duplicate is gone by the time the canonicaliser sees it. This set carries
raw input bytes instead, and pins the accept/reject verdict a conforming parser
must reach BEFORE canonicalisation runs.

Normative anchor: RFC 8259 section 4.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

CANON_VERSION = "jcs-rfc8785-v1"


def b64(raw: str) -> str:
    return base64.b64encode(raw.encode("utf-8")).decode("ascii")


ACCEPT = [
    {
        "id": "ok-control",
        "description": "All member names unique at every level. Baseline that must parse.",
        "input": '{"amount":1000000,"type":"spend_decision"}',
    },
    {
        "id": "ok-same-name-in-sibling-objects",
        "description": (
            "The same member name appearing in two DIFFERENT objects is legal and "
            "must not be rejected. Guards against a checker that flattens paths or "
            "tracks names globally instead of per object."
        ),
        "input": '{"a":{"id":"x"},"b":{"id":"y"}}',
    },
    {
        "id": "ok-name-repeated-across-array-elements",
        "description": (
            "The same member name in successive array elements is legal. Guards "
            "against a checker that walks members without resetting per object."
        ),
        "input": '{"items":[{"id":"x"},{"id":"y"}]}',
    },
]

REJECT = [
    {
        "id": "rj-duplicate-top-level",
        "description": "Duplicate member name at the top level.",
        "input": '{"a":1,"a":2}',
        "expected_code": "REJECT_DUPLICATE_MEMBER",
        "why": (
            "RFC 8259 section 4: names within an object SHOULD be unique, and when "
            "they are not the behaviour of receiving software is unpredictable."
        ),
    },
    {
        "id": "rj-duplicate-nested",
        "description": "Duplicate member name inside a nested object.",
        "input": '{"outer":{"b":1,"b":2}}',
        "expected_code": "REJECT_DUPLICATE_MEMBER",
        "why": "A top-level-only check misses this; the rule is per object at every depth.",
    },
    {
        "id": "rj-duplicate-in-array-element",
        "description": "Duplicate member name inside an object nested in an array.",
        "input": '{"items":[{"c":1,"c":2}]}',
        "expected_code": "REJECT_DUPLICATE_MEMBER",
        "why": "Array traversal must still apply the per-object uniqueness rule.",
    },
    {
        "id": "rj-duplicate-identical-values",
        "description": (
            "Duplicate member name whose two values are identical. Still rejected: "
            "the rule is structural, not value-based."
        ),
        "input": '{"a":1,"a":1}',
        "expected_code": "REJECT_DUPLICATE_MEMBER",
        "why": (
            "A de-duplicating check that compares values would accept this and then "
            "silently accept the divergent case too once values differ."
        ),
    },
    {
        "id": "rj-duplicate-divergent-evidence",
        "description": (
            "The evidence case. Raw bytes carry two different values for one name, "
            "so a first-wins reader and a last-wins reader disagree about what the "
            "document says while any signature over the parsed value still verifies."
        ),
        "input": '{"task_type":"decoy","task_type":"private_matter"}',
        "expected_code": "REJECT_DUPLICATE_MEMBER",
        "why": (
            "RFC 8259 section 4 records all three real behaviours: last-only, parse "
            "error, and report-all. A signed artifact whose meaning depends on which "
            "parser opens it is not evidence."
        ),
    },
]


def build() -> dict:
    for v in ACCEPT + REJECT:
        raw = v.pop("input")
        v["input_b64"] = b64(raw)
        v["input_sha256"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()

    return {
        "set": "jcs_parse_v1",
        "schema_version": "1.0.0",
        "license": "Apache-2.0",
        "copyright": "Copyright 2026 AlgoVoi (chopmob@gmail.com)",
        "spec": "RFC 8259 section 4 (object member uniqueness), as a parse-layer precondition for RFC 8785 canonicalisation",
        "spec_authorship": (
            "AlgoVoi-authored conformance set. RFC 8785 canonicalises an already-parsed "
            "value, so duplicate member names cannot be represented in a parsed-input "
            "vector set: the duplicate is gone before the canonicaliser runs. This set "
            "carries raw input bytes and pins the verdict a conforming parser must reach "
            "first. Normative reference: RFC 8259 section 4."
        ),
        "canon_version": CANON_VERSION,
        "description": (
            "Parse-layer preconditions for canonicalisation. Inputs are raw UTF-8 bytes "
            "(base64) because the defect being pinned does not survive parsing. Each "
            "vector states whether a conforming parser accepts the bytes or rejects them "
            "with a named code, BEFORE any canonical form is computed."
        ),
        "reject_codes": ["REJECT_DUPLICATE_MEMBER"],
        "accept": ACCEPT,
        "reject": REJECT,
        "invariants": [
            {
                "name": "duplicates_are_invisible_after_parsing",
                "relation": "parse_layer_only",
                "why": (
                    "json.loads('{\"a\":1,\"a\":2}') yields {'a': 2}. Canonicalising that "
                    "parsed value produces valid canonical bytes for a document the raw "
                    "input did not unambiguously state. No canonicalisation vector can "
                    "detect this, which is why the check belongs at parse."
                ),
            },
            {
                "name": "structural_not_value_based",
                "a": "rj-duplicate-identical-values",
                "b": "rj-duplicate-divergent-evidence",
                "relation": "both_reject",
                "why": (
                    "Rejection must not depend on whether the duplicated values differ. "
                    "A value-comparing check passes the identical case and establishes a "
                    "code path that later accepts the divergent one."
                ),
            },
            {
                "name": "per_object_not_global",
                "a": "ok-same-name-in-sibling-objects",
                "b": "rj-duplicate-nested",
                "relation": "accept_then_reject",
                "why": (
                    "Uniqueness is scoped to a single object. A checker tracking names "
                    "globally raises a false positive on the accept vector; one checking "
                    "only the top level misses the reject vector."
                ),
            },
        ],
    }


if __name__ == "__main__":
    out = build()
    Path("jcs_parse_v1.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"wrote jcs_parse_v1.json: {len(out['accept'])} accept, {len(out['reject'])} reject")
