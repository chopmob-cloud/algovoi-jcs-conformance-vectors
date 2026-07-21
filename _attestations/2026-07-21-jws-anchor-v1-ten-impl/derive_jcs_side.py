#!/usr/bin/env python3
"""Derive the JCS-side fixture for the jws_anchor_v1 ten-implementation run.

jws_anchor_v1 pins the ANCHORING rule: for a signed token you hash the raw signed
bytes, and only an unsigned object is anchored by sha256(JCS(object)). Five of its
six vectors are therefore `signed_bytes` and are not canonicalisation vectors at
all. This script extracts the three places where the set does depend on RFC 8785
canonicalisation, so those can be cross-validated across all ten implementations
using the corpus's existing generic preimage runners:

  jws-anchor-005  the unsigned_jcs vector: anchor = sha256(JCS(object))
  jws-anchor-002  the recanon negative: sha256(JCS(decoded payload of 001))
  jws-anchor-006  the canon-sensitive recanon, whose payload carries U+2028 and
                  the 1.0 integral-float form, i.e. a jcs_edge_v1 class case

Output matches the shape the corpus's generic runners already expect
(preimage / expected_jcs_bytes_b64 / expected_content_sha256), so no runner needs
changing. Signature verification is NOT covered here: that runs separately on the
crypto-capable subset, and the attestation records the split explicitly.

Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0.
"""
from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import sys

import rfc8785

HERE = pathlib.Path(__file__).resolve().parent
SET = HERE.parent.parent / "vectors" / "jws_anchor_v1" / "jws_anchor_v1.json"
OUT = HERE / "jws_anchor_v1_jcs_side.json"


def b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def payload_of(token: str) -> dict:
    """Decode the payload of a compact JWS (header.payload.signature)."""
    return json.loads(b64url_decode(token.split(".")[1]))


def strip(h: str) -> str:
    return h.split(":", 1)[1] if ":" in h else h


def main() -> int:
    data = json.loads(SET.read_text(encoding="utf-8"))
    by_id = {v["vector_id"]: v for v in data["vectors"]}

    derived = [
        # the one genuinely unsigned vector: JCS is the anchor rule
        ("jws-anchor-005-jcs", by_id["jws-anchor-005"]["input"],
         strip(by_id["jws-anchor-005"]["expected_anchor"]),
         "unsigned object anchored by sha256(JCS(object))"),
        # the recanonicalisation negatives: what you get if you wrongly re-canonicalise
        ("jws-anchor-002-recanon", payload_of(by_id["jws-anchor-001"]["input"]),
         strip(by_id["jws-anchor-002"]["recanon_of_decoded_payload"]),
         "sha256(JCS(decoded payload of jws-anchor-001)); MUST NOT equal that vector's anchor"),
        ("jws-anchor-006-recanon", payload_of(by_id["jws-anchor-006"]["input"]),
         strip(by_id["jws-anchor-006"]["recanon_of_decoded_payload"]),
         "sha256(JCS(decoded payload of jws-anchor-006)); payload carries U+2028 and 1.0, "
         "so this is a jcs_edge_v1 class case"),
    ]

    vectors = []
    for vid, preimage, expected_sha, note in derived:
        canon = rfc8785.dumps(preimage)
        digest = hashlib.sha256(canon).hexdigest()
        if digest != expected_sha:
            print(f"  MISMATCH {vid}: derived {digest} != set {expected_sha}", file=sys.stderr)
            return 1
        vectors.append({
            "vector_id": vid,
            "description": note,
            "preimage": preimage,
            "expected_jcs_bytes_b64": base64.b64encode(canon).decode(),
            "expected_content_sha256": digest,
        })

    out = {
        "set": "jws_anchor_v1_jcs_side",
        "derived_from": "vectors/jws_anchor_v1/jws_anchor_v1.json",
        "description": (
            "JCS-side projection of jws_anchor_v1 for ten-implementation cross-validation. "
            "Each vector asserts sha256(JCS(preimage)) and the canonical bytes themselves. "
            "The signed_bytes anchoring rule and Ed25519 verification are validated separately "
            "on the crypto-capable subset."
        ),
        "license": "Apache-2.0",
        "copyright": "Copyright 2026 AlgoVoi (chopmob@gmail.com)",
        "vectors": vectors,
    }
    OUT.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="")
    print(f"wrote {OUT.name}: {len(vectors)} vectors, all reproduced from the set")
    for v in vectors:
        print(f"  {v['vector_id']}: {v['expected_content_sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
