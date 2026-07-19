#!/usr/bin/env python3
# Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE at the repo root.
"""
jcs_edge_v1 generator.

Pins the three RFC 8785 canonicalisation edge classes that ad-hoc "sorted-keys
JSON" gets wrong and that a single-SDK self-check cannot catch:

  1. UTF-8 Generation (RFC 8785 section 3.2.4): U+2028 / U+2029 (line and
     paragraph separators) MUST be emitted as literal UTF-8 bytes, never as
     backslash-u escapes. Go's encoding/json escapes them even with
     SetEscapeHTML(false); a conformant JCS serialiser does not.
  2. Object property ordering (RFC 8785 section 3.2.3): property names are sorted
     by their UTF-16 code units, NOT by Unicode code point. The two diverge for
     supplementary-plane characters (a surrogate pair's lead unit 0xD800..0xDBFF
     sorts below U+FFFF).
  3. Number form (RFC 8785 section 3.2.2.3 / ES6): 1.0 and 1 canonicalise to the
     same bytes.

Also pins the mandatory short escapes (3.2.2.2) and that solidus / and- / less-
than / greater-than stay literal (contrast with HTML escaping).

Source is pure ASCII: every special character is written as a Python escape so no
code page can mangle it. The vector file stores preimage strings as ASCII escapes
too (portable across every JSON parser); the canonical bytes appear only as
base64. Expected values are produced by the reference implementation (Python
rfc8785, Trail of Bits) and are what all ten corpus implementations must reproduce
byte-for-byte.
"""
from __future__ import annotations
import base64, hashlib, json
from pathlib import Path
import rfc8785

HERE = Path(__file__).parent
OUT = HERE / "jcs_edge_v1.json"

SEP_L = chr(0x2028)        # line separator
SEP_P = chr(0x2029)        # paragraph separator
FFFF = chr(0xFFFF)         # highest BMP code point
GRIN = chr(0x1F600)        # supplementary plane (surrogate pair 0xD83D 0xDE00)
PILE = chr(0x1F4A9)        # supplementary plane (surrogate pair 0xD83D 0xDCA9)
EACUTE = chr(0xE9)         # precomposed e-acute (NFC)
CONTROLS = chr(0) + chr(1) + chr(0x1F)  # control chars with no short escape


def enc(obj):
    b = rfc8785.dumps(obj)
    return b, base64.b64encode(b).decode("ascii"), hashlib.sha256(b).hexdigest()


def vec(vid, desc, section, preimage, expectation):
    b, b64, sha = enc(preimage)
    return {
        "vector_id": vid,
        "description": desc,
        "rfc8785_section": section,
        "expectation": expectation,
        "preimage": preimage,
        "expected_jcs_bytes_b64": b64,
        "expected_sha256": sha,
        # Aliases so the corpus's existing generic base-language runners
        # (which read `receipt` + `expected_content_hash`) validate this set
        # unchanged; identical to preimage / expected_sha256 above.
        "receipt": preimage,
        "expected_content_hash": sha,
    }


vectors = [
    vec("jcs-edge-001-sep-in-value",
        "U+2028 and U+2029 inside a string value serialise as literal UTF-8 (e2 80 a8 / e2 80 a9), not their backslash-u escapes.",
        "3.2.4",
        {"k": "a" + SEP_L + "b" + SEP_P + "c"},
        "literal-utf8-separators"),
    vec("jcs-edge-002-sep-in-key",
        "U+2028 inside a property name serialises as literal UTF-8 in the key too.",
        "3.2.4",
        {"a" + SEP_L + "b": "x"},
        "literal-utf8-separator-in-key"),
    vec("jcs-edge-003-nonbmp-key-order",
        "Keys U+FFFF (BMP) and U+1F600 (supplementary) sort by UTF-16 code units: the emoji (lead unit 0xD83D) precedes U+FFFF. Code-point ordering would reverse them.",
        "3.2.3",
        {FFFF: 1, GRIN: 2},
        "utf16-code-unit-order-emoji-first"),
    vec("jcs-edge-004-nonbmp-key-order-multi",
        "Mixed BMP and supplementary keys; canonical order is by UTF-16 code units throughout.",
        "3.2.3",
        {GRIN: 1, FFFF: 2, EACUTE: 3, "z": 4, PILE: 5},
        "utf16-code-unit-order-multi"),
    vec("jcs-edge-005-number-one-float",
        "1.0 canonicalises to the integer form 1.",
        "3.2.2.3",
        {"n": 1.0},
        "number-1"),
    vec("jcs-edge-006-number-one-int",
        "1 canonicalises to 1 (byte-identical to the 1.0 case).",
        "3.2.2.3",
        {"n": 1},
        "number-1"),
    vec("jcs-edge-007-mandatory-short-escapes",
        "Backspace, form feed, newline, carriage return and tab use the two-character short escapes.",
        "3.2.2.2",
        {"s": "\b\f\n\r\t"},
        "short-escapes"),
    vec("jcs-edge-008-control-u-escape",
        "Control characters without a short escape use the lowercase backslash-u-00xx form.",
        "3.2.2.2",
        {"s": CONTROLS},
        "u00xx-escapes"),
    vec("jcs-edge-009-solidus-and-html-literal",
        "Solidus and the and- / less-than / greater-than characters stay literal (JCS does not HTML-escape).",
        "3.2.2.2",
        {"s": "a/b&c<d>e"},
        "literal-solidus-and-html"),
    vec("jcs-edge-010-accented-nfc-literal",
        "A precomposed (NFC) accented character serialises as literal UTF-8; JCS applies no Unicode normalisation.",
        "3.2.4",
        {"s": "caf" + EACUTE},
        "literal-utf8-accented"),
]

pair_invariants = [
    {
        "name": "number_form_1.0_equals_1",
        "a": "jcs-edge-005-number-one-float",
        "b": "jcs-edge-006-number-one-int",
        "relation": "equal_sha256",
        "why": "1.0 and 1 produce byte-identical canonical output; a serialiser that preserves the trailing .0 diverges.",
    },
    {
        "name": "nonbmp_order_is_utf16_not_codepoint",
        "vector": "jcs-edge-003-nonbmp-key-order",
        "relation": "emoji_key_precedes_ffff",
        "why": "Under UTF-16 code-unit ordering the U+1F600 key precedes the U+FFFF key; under code-point ordering it would follow. The expected bytes encode the UTF-16 order.",
    },
]

by_id = {v["vector_id"]: v for v in vectors}
assert by_id["jcs-edge-005-number-one-float"]["expected_sha256"] == by_id["jcs-edge-006-number-one-int"]["expected_sha256"], "1.0 != 1"
b3 = base64.b64decode(by_id["jcs-edge-003-nonbmp-key-order"]["expected_jcs_bytes_b64"])
assert b3.index(b"\xf0\x9f\x98\x80") < b3.index(b"\xef\xbf\xbf"), "emoji key not first"

doc = {
    "name": "jcs_edge_v1",
    "license": "Apache-2.0",
    "copyright": "Copyright 2026 AlgoVoi (chopmob@gmail.com)",
    "spec": "RFC 8785 (JCS) canonicalisation edge cases",
    "spec_authorship": "AlgoVoi-authored conformance set. Normative reference: RFC 8785 sections 3.2.2.2, 3.2.2.3, 3.2.3, 3.2.4. Pins the UTF-8 generation, property-ordering and number-form cases that ad-hoc canonicalisers and single-SDK self-checks miss.",
    "canon_version": "jcs-rfc8785-v1",
    "reference_impl": "Python rfc8785 0.1.4 (Trail of Bits)",
    "vectors": vectors,
    "pair_invariants": pair_invariants,
}

OUT.write_text(json.dumps(doc, ensure_ascii=True, indent=2) + "\n", encoding="ascii", newline="")
print(f"wrote {OUT} : {len(vectors)} vectors, {len(pair_invariants)} pair invariants")
print("source pure-ASCII:", Path(__file__).read_bytes().isascii())
print("output pure-ASCII:", OUT.read_bytes().isascii())
for v in vectors:
    print(f"  {v['vector_id']:38s} sha={v['expected_sha256'][:16]}")
