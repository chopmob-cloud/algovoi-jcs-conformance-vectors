#!/usr/bin/env python3
# Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE in this directory.
#
# jws_anchor_v1 runner (Python). Verifies every signed token under the RFC 8032
# section 7.1 public key, recomputes each anchor from the token/object bytes, and
# checks the negatives and invariants. No value is copied from the vector: every
# expected_anchor is recomputed from the input and compared.

import base64
import hashlib
import json
import sys

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def anchor(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def decoded_payload(compact_jws: str) -> dict:
    return json.loads(b64u_dec(compact_jws.split(".")[1]))


def verify_sig(compact_jws: str, pk_hex: str) -> bool:
    pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex))
    h, p, s = compact_jws.split(".")
    try:
        pk.verify(b64u_dec(s), (h + "." + p).encode("ascii"))
        return True
    except InvalidSignature:
        return False


def main(path: str) -> int:
    d = json.load(open(path, encoding="utf-8"))
    V = {v["vector_id"]: v for v in d["vectors"]}
    ok = 0
    fail = 0

    def check(cond, label):
        nonlocal ok, fail
        if cond:
            ok += 1
        else:
            fail += 1
            print("  FAIL", label)

    for v in d["vectors"]:
        vid, case = v["vector_id"], v["case"]
        if case in ("signed_jws_anchor", "canon_sensitive_signed"):
            check(verify_sig(v["input"], v["signing"]["public_key_hex"]), f"{vid} sig")
            check(anchor(v["input"].encode("ascii")) == v["expected_anchor"], f"{vid} anchor")
            if "recanon_of_decoded_payload" in v:
                rec = anchor(rfc8785.dumps(decoded_payload(v["input"])))
                check(rec == v["recanon_of_decoded_payload"], f"{vid} recanon-value")
                check(rec != v["expected_anchor"], f"{vid} recanon-diverges")
        elif case == "recanon_negative":
            src = V[v["ties_to"]]["input"]
            rec = anchor(rfc8785.dumps(decoded_payload(src)))
            check(rec == v["recanon_of_decoded_payload"], f"{vid} recanon-value")
            check(rec != v["must_not_equal"], f"{vid} != signed anchor")
        elif case == "sd_jwt_issuer":
            check(verify_sig(v["issuer_jwt"], v["signing"]["public_key_hex"]), f"{vid} sig")
            check(anchor(v["issuer_jwt"].encode("ascii")) == v["expected_anchor"], f"{vid} anchor")
        elif case == "sd_jwt_presentation":
            issuer = V[v["ties_to"]]
            ph = anchor(v["presentation"].encode("ascii"))
            ih = anchor(issuer["issuance_form"].encode("ascii"))
            check(ph == v["presentation_hash"], f"{vid} presentation-hash")
            check(ih == v["issuance_hash"], f"{vid} issuance-hash")
            check(ph != v["must_not_equal"], f"{vid} presentation != issuer JWT")
            check(ih != v["must_not_equal"], f"{vid} issuance != issuer JWT")
            check(ph != ih, f"{vid} presentation != issuance")
        elif case == "unsigned_jcs":
            check(anchor(rfc8785.dumps(v["input"])) == v["expected_anchor"], f"{vid} jcs-anchor")
        else:
            check(False, f"{vid} unknown case {case}")

    # invariants
    check(V["jws-anchor-002"]["recanon_of_decoded_payload"] != V["jws-anchor-001"]["expected_anchor"], "I1")
    check(V["jws-anchor-004"]["presentation_hash"] != V["jws-anchor-003"]["expected_anchor"]
          and V["jws-anchor-004"]["issuance_hash"] != V["jws-anchor-003"]["expected_anchor"], "I2")
    check(V["jws-anchor-006"]["recanon_of_decoded_payload"] != V["jws-anchor-006"]["expected_anchor"], "I4")

    total = ok + fail
    print(f"{ok}/{total} PASS" if fail == 0 else f"{ok}/{total} PASS, {fail} FAIL")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "jws_anchor_v1.json"))
