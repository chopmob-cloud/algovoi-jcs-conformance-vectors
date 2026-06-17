"""
settlement_action_binding_v1 runner (Python).

Validates the 6 vectors + 5 pair invariants in settlement_action_binding_v1.json using
algovoi-substrate (>=0.4.0) on PyPI. Composes action_ref_exactly_once_v1 (action_ref +
transition_hash), settlement_attestation_v1 (settlement_ref) and retention_chain_v1
(retention_chain_ref) into one post-settlement accountability binding:

    binding_ref = "sha256:" + SHA-256(JCS({action_ref, transition_hash,
                                           settlement_ref, retention_chain_ref}))

For each vector the runner: (1) re-canonicalises the preimage and checks the JCS bytes,
(2) checks the bare SHA-256 digest (the 8-lang byte claim), (3) checks the "sha256:"-prefixed
binding_ref, and (4) cross-checks against the substrate primitive
`settlement_action_binding(...)`. Then verifies the 5 pair invariants on binding_ref.

Usage:
    pip install algovoi-substrate>=0.4.0
    python runner_python.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from algovoi_substrate import canonicalize, settlement_action_binding

VECTORS_FILE = Path(__file__).parent / "settlement_action_binding_v1.json"


def main() -> int:
    data = json.loads(VECTORS_FILE.read_text(encoding="utf-8"))
    vectors = {v["vector_id"]: v for v in data["vectors"]}
    failures: list[str] = []

    print("settlement_action_binding_v1 runner (Python / algovoi-substrate)")
    print(f"vectors: {len(vectors)}, pair invariants: {len(data['pair_invariants'])}")
    print()

    for vid, v in vectors.items():
        pre = v["preimage"]
        canon = canonicalize(pre)
        canon_bytes = canon.encode("utf-8") if isinstance(canon, str) else canon

        actual_b64 = base64.b64encode(canon_bytes).decode("ascii")
        if actual_b64 != v["expected_jcs_bytes_b64"]:
            failures.append(f"{vid}: JCS bytes b64 mismatch")
            print(f"  {vid}: FAIL (b64 mismatch)")
            continue

        digest = hashlib.sha256(canon_bytes).hexdigest()
        if digest != v["expected_content_sha256"]:
            failures.append(f"{vid}: bare SHA-256 mismatch")
            print(f"  {vid}: FAIL (SHA-256 mismatch)")
            continue

        reconstructed = "sha256:" + digest
        if reconstructed != v["expected_binding_ref"]:
            failures.append(f"{vid}: binding_ref reconstruction mismatch")
            print(f"  {vid}: FAIL (binding_ref reconstruction)")
            continue

        primitive = settlement_action_binding(
            pre["action_ref"], pre["transition_hash"],
            pre["settlement_ref"], pre["retention_chain_ref"])
        if primitive != v["expected_binding_ref"]:
            failures.append(f"{vid}: settlement_action_binding() primitive mismatch")
            print(f"  {vid}: FAIL (substrate primitive mismatch)")
            continue

        print(f"  {vid}: PASS  {v['pair_group']:10s} {v['expected_binding_ref']}")

    print()

    def _ref(vid: str) -> str:
        return vectors[vid]["expected_binding_ref"]

    for pair in data["pair_invariants"]:
        lh, rh = _ref(pair["left"]), _ref(pair["right"])
        if pair["type"] == "different_hash_from":
            if lh == rh:
                failures.append(f"{pair['id']}: different_hash_from violated (binding_refs collide)")
                print(f"  {pair['id']}: FAIL (binding_refs collide)")
            else:
                print(f"  {pair['id']}: PASS  {pair['left']} != {pair['right']}")
        elif pair["type"] == "same_hash_as":
            if lh != rh:
                failures.append(f"{pair['id']}: same_hash_as violated (binding_refs differ)")
                print(f"  {pair['id']}: FAIL (binding_refs differ)")
            else:
                print(f"  {pair['id']}: PASS  {pair['left']} == {pair['right']} (stable)")

    print()
    if failures:
        print(f"FAILED: {len(failures)} issue(s)")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"PASS: {len(vectors)} vectors + {len(data['pair_invariants'])} pair invariants "
          f"validated against algovoi-substrate.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
