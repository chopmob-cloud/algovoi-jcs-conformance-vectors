"""epi_pqc_v0 runner (Python).

Recomputes frame_id + JCS bytes for every vector straight from its input, verifies the optional
falcon1024 signature-suite anchor, and verifies the F7 key-lineage anchor — all offline, from the
published public keys. No AlgoVoi code; trust base is two public libraries.

Usage:
    pip install rfc8785>=0.1.2 pqcrypto>=0.4.0
    python runner_python.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import os

import rfc8785
from pqcrypto.sign.falcon_1024 import verify as falcon_verify


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


def _kid(pk: bytes) -> str:
    return hashlib.sha256(pk).hexdigest()[:16]


def _falcon_ok(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        return bool(falcon_verify(pk, msg, sig))
    except Exception:  # noqa: BLE001
        return False


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    doc = json.load(open(os.path.join(here, "epi_pqc_v0.json"), encoding="utf-8"))
    failures = 0

    # 1. JCS canonicalisation vectors reproduce
    for v in doc["vectors"]:
        jcs = rfc8785.dumps(v["input"])
        b64 = base64.b64encode(jcs).decode("ascii")
        frame_id = "sha256:" + hashlib.sha256(jcs).hexdigest()
        ok = b64 == v["expected_jcs_bytes_b64"] and frame_id == v["frame_id"]
        print(("PASS" if ok else "FAIL"), v["id"], v["source_name"], v["frame_id"])
        failures += 0 if ok else 1

    # 2. falcon1024 signature-suite anchor verifies over the canonical message
    sa = doc["signature_suite_anchor"]
    msg_vec = next(v for v in doc["vectors"] if v["id"] == sa["message_vector_id"])
    msg = rfc8785.dumps(msg_vec["input"])
    pk = base64.b64decode(sa["public_key_b64"])
    ok = (_kid(pk) == sa["kid"]
          and "sha256:" + hashlib.sha256(msg).hexdigest() == sa["message_frame_id"]
          and _falcon_ok(pk, msg, _b64u(sa["signature_b64url"])))
    print(("PASS" if ok else "FAIL"), "signature_suite_anchor", sa["suite"], sa["kid"])
    failures += 0 if ok else 1

    # 3. key-lineage anchor: each rotation proof cross-verifies, and the lineage is unbroken
    prev_new = None
    for i, p in enumerate(doc["key_lineage_anchor"]["proofs"]):
        binding = {k: p[k] for k in ("old_kid", "new_kid", "old_pubkey_b64", "new_pubkey_b64", "rotated_at")}
        bmsg = rfc8785.dumps(binding)
        opk = base64.b64decode(p["old_pubkey_b64"])
        npk = base64.b64decode(p["new_pubkey_b64"])
        ok = (_kid(opk) == p["old_kid"] and _kid(npk) == p["new_kid"]
              and _falcon_ok(opk, bmsg, _b64u(p["old_sig"]))
              and _falcon_ok(npk, bmsg, _b64u(p["new_sig"]))
              and (prev_new is None or p["old_kid"] == prev_new))
        print(("PASS" if ok else "FAIL"), f"key_lineage[{i}]", p["old_kid"], "->", p["new_kid"])
        prev_new = p["new_kid"]
        failures += 0 if ok else 1

    total = len(doc["vectors"]) + 1 + len(doc["key_lineage_anchor"]["proofs"])
    print(f"\n{total - failures}/{total} checks reproduce")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
