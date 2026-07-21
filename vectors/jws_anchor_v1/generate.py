#!/usr/bin/env python3
# Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE in this directory.
#
# Generates jws_anchor_v1.json: the signed-token ANCHORING conformance floor.
#
# jcs_edge_v1 pins the canonicalisation floor (given an object, the exact canonical
# bytes). This set pins the layer above it: given a *signed* object, WHICH BYTES
# you hash when you anchor it. The failure this catches is subtle because both
# parties can be perfectly JCS-conformant and still disagree on the anchor:
#
#   - anchor a signed token by hashing what was signed (the compact JWS bytes), OR
#   - re-canonicalise the decoded payload and hash that (a different byte string,
#     so the anchor no longer binds the signed artifact), OR
#   - anchor a selective-disclosure *presentation* (whose bytes vary by disclosure)
#     instead of the issuer's frozen commitment.
#
# All fixtures are signed with the RFC 8032 section 7.1 Test 1 Ed25519 keypair
# (the same deterministic key used in rfc9421_proxy_chain_v0). EdDSA is
# deterministic, so every token and every anchor below is reproducible by anyone.
# Tokens are embedded as ASCII strings; runners verify + hash, they do not re-sign.

import base64
import hashlib
import json

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# RFC 8032 section 7.1, Test 1
SK_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
PK_HEX = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
_SK = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SK_HEX))


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def sha_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def anchor(b: bytes) -> str:
    return "sha256:" + sha_hex(b)


def jws_compact(header: dict, payload_bytes: bytes) -> str:
    """A compact JWS (EdDSA). payload_bytes is the exact payload the issuer signs,
    passed in so a canon-sensitive case can control the issuer serialisation."""
    hdr = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signing_input = (b64u(hdr) + "." + b64u(payload_bytes)).encode("ascii")
    sig = _SK.sign(signing_input)
    return signing_input.decode("ascii") + "." + b64u(sig)


def disclosure(salt: str, name: str, value) -> str:
    return b64u(json.dumps([salt, name, value], separators=(",", ":")).encode("utf-8"))


def sd_digest(disc: str) -> str:
    return b64u(hashlib.sha256(disc.encode("ascii")).digest())


HDR = {"alg": "EdDSA", "typ": "JWT"}
HDR_SD = {"alg": "EdDSA", "typ": "sd-jwt"}

vectors = []

# ---- A: signed_jws_anchor (positive) -------------------------------------------
p1 = {
    "iss": "did:example:issuer",
    "iat": 1721000000,
    "mandate_type": "payment",
    "amount": {"currency": "USD", "value": "100.00"},
    "recipient": "did:example:merchant",
}
p1_bytes = json.dumps(p1, separators=(",", ":"), sort_keys=True).encode("utf-8")
jws1 = jws_compact(HDR, p1_bytes)
vectors.append({
    "vector_id": "jws-anchor-001",
    "case": "signed_jws_anchor",
    "description": "Anchor a signed compact JWS by hashing the token bytes as issued.",
    "anchor_rule": "signed_bytes",
    "input": jws1,
    "signing": {"key_ref": "rfc8032-7.1-test1", "alg": "EdDSA", "public_key_hex": PK_HEX},
    "expected_anchor": anchor(jws1.encode("ascii")),
})

# ---- B: recanon_negative (tied to A) -------------------------------------------
# Decode the payload and JCS it: a different byte string, so a different hash.
p1_decoded = json.loads(base64.urlsafe_b64decode(jws1.split(".")[1] + "=="))
vectors.append({
    "vector_id": "jws-anchor-002",
    "case": "recanon_negative",
    "description": "Re-canonicalising the decoded payload (JCS) does NOT reproduce the "
                   "signed-token anchor; a verifier that re-serialises binds nothing signed.",
    "anchor_rule": "signed_bytes",
    "ties_to": "jws-anchor-001",
    "recanon_of_decoded_payload": anchor(rfc8785.dumps(p1_decoded)),
    "must_not_equal": anchor(jws1.encode("ascii")),
})

# ---- C: sd_jwt_issuer ----------------------------------------------------------
d_amount = disclosure("salt-amount-01", "amount", {"currency": "USD", "value": "100.00"})
d_recipient = disclosure("salt-recip-01", "recipient", "did:example:merchant")
p3 = {
    "iss": "did:example:issuer",
    "iat": 1721000000,
    "_sd_alg": "sha-256",
    "_sd": sorted([sd_digest(d_amount), sd_digest(d_recipient)]),
    "mandate_type": "payment",
}
p3_bytes = json.dumps(p3, separators=(",", ":"), sort_keys=True).encode("utf-8")
issuer_jwt = jws_compact(HDR_SD, p3_bytes)
issuer_sdjwt = issuer_jwt + "~" + d_amount + "~" + d_recipient + "~"
vectors.append({
    "vector_id": "jws-anchor-003",
    "case": "sd_jwt_issuer",
    "description": "SD-JWT: the stable anchor is over the issuer-signed JWT (the segment "
                   "before the first ~), which is disclosure-invariant.",
    "anchor_rule": "signed_bytes",
    "issuer_jwt": issuer_jwt,
    "issuance_form": issuer_sdjwt,
    "signing": {"key_ref": "rfc8032-7.1-test1", "alg": "EdDSA", "public_key_hex": PK_HEX},
    "expected_anchor": anchor(issuer_jwt.encode("ascii")),
})

# ---- D: sd_jwt_presentation (tied to C) ----------------------------------------
presentation = issuer_jwt + "~" + d_amount + "~"
vectors.append({
    "vector_id": "jws-anchor-004",
    "case": "sd_jwt_presentation",
    "description": "A holder presentation discloses a subset, so its bytes differ from the "
                   "issuance form AND from the issuer JWT. Anchor the issuer JWT, not a presentation.",
    "anchor_rule": "signed_bytes",
    "ties_to": "jws-anchor-003",
    "presentation": presentation,
    "presentation_hash": anchor(presentation.encode("ascii")),
    "issuance_hash": anchor(issuer_sdjwt.encode("ascii")),
    "must_not_equal": anchor(issuer_jwt.encode("ascii")),
})

# ---- E: unsigned_jcs (crossover to jcs_edge_v1's rule) -------------------------
obj = {"amount": {"currency": "USD", "value": "1"}, "decision": "ALLOW",
       "subject_ref": "sha256:" + "0" * 64}
vectors.append({
    "vector_id": "jws-anchor-005",
    "case": "unsigned_jcs",
    "description": "A bare unsigned object has no signed byte form, so the anchor is JCS "
                   "then SHA-256 (RFC 8785) -- the jcs_edge_v1 rule.",
    "anchor_rule": "jcs",
    "input": obj,
    "expected_anchor": anchor(rfc8785.dumps(obj)),
})

# ---- F: canon_sensitive_signed (ties the two sets) -----------------------------
# Issuer signs a payload whose JCS form differs on a jcs_edge_v1 case: the value 1.0
# (JCS folds to 1) and a U+2028 in a string (JCS emits literal UTF-8, json.dumps
# escapes). The signed bytes are the issuer's serialisation; JCS(decoded) differs
# *because of* the canonicalisation edge, so the anchors diverge for that reason.
p6_obj = {"iss": "did:example:issuer", "note": "line1 line2", "qty": 1.0}
p6_bytes = json.dumps(p6_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
jws6 = jws_compact(HDR, p6_bytes)
p6_decoded = json.loads(base64.urlsafe_b64decode(jws6.split(".")[1] + "=="))
vectors.append({
    "vector_id": "jws-anchor-006",
    "case": "canon_sensitive_signed",
    "description": "The signed-vs-recanonicalised divergence is worst exactly where "
                   "jcs_edge_v1 lives: a U+2028 string and the value 1.0 both canonicalise "
                   "differently than the issuer serialised them.",
    "anchor_rule": "signed_bytes",
    "input": jws6,
    "signing": {"key_ref": "rfc8032-7.1-test1", "alg": "EdDSA", "public_key_hex": PK_HEX},
    "expected_anchor": anchor(jws6.encode("ascii")),
    "recanon_of_decoded_payload": anchor(rfc8785.dumps(p6_decoded)),
    "must_not_equal": anchor(jws6.encode("ascii")),
    "xref": "jcs_edge_v1",
}, )

doc = {
    "set": "jws_anchor_v1",
    "schema_version": "1.0",
    "description": "Signed-token anchoring conformance: which bytes an implementation must "
                   "hash when it anchors a signed receipt/mandate. Sibling to jcs_edge_v1, "
                   "one layer up. All tokens signed with the RFC 8032 section 7.1 Test 1 "
                   "Ed25519 keypair; every anchor is reproducible.",
    "canonicalizer": "RFC 8785 (JCS) for unsigned objects; raw signed bytes for signed tokens",
    "signing_key": {"alg": "EdDSA", "curve": "Ed25519", "ref": "rfc8032-7.1-test1",
                    "public_key_hex": PK_HEX},
    "license": "Apache-2.0",
    "copyright": "Copyright 2026 AlgoVoi (chopmob@gmail.com)",
    "vectors": vectors,
    "invariants": [
        {"id": "I1", "statement": "recanon(decoded payload) != signed-token anchor",
         "check": "jws-anchor-002.recanon_of_decoded_payload != jws-anchor-001.expected_anchor"},
        {"id": "I2", "statement": "issuer-JWT anchor is disclosure-invariant; presentation "
                                  "!= issuance != issuer JWT",
         "check": "jws-anchor-004.presentation_hash != jws-anchor-004.issuance_hash != "
                  "jws-anchor-003.expected_anchor"},
        {"id": "I3", "statement": "every signed token verifies under the RFC 8032 7.1 public key"},
        {"id": "I4", "statement": "canon-sensitive divergence is attributable to a jcs_edge_v1 "
                                  "case (U+2028, 1.0)", "xref": "jcs_edge_v1"},
    ],
}

if __name__ == "__main__":
    out = json.dumps(doc, indent=2, ensure_ascii=True)
    assert out.isascii()
    with open("jws_anchor_v1.json", "w", encoding="utf-8", newline="\n") as f:
        f.write(out + "\n")
    print("wrote jws_anchor_v1.json:", len(vectors), "vectors,", len(doc["invariants"]), "invariants")
