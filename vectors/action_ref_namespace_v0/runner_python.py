"""
action_ref_namespace_v0 runner (Python).

Validates the 8 vectors + 4 pair invariants in action_ref_namespace_v0.json
using algovoi-substrate (>=0.2.1) on PyPI.

Usage:
    pip install algovoi-substrate>=0.2.1
    python runner_python.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from algovoi_substrate import action_ref, canonicalize

VECTORS_FILE = Path(__file__).parent / "action_ref_namespace_v0.json"


def main() -> int:
    data = json.loads(VECTORS_FILE.read_text(encoding="utf-8"))
    vectors = {v["vector_id"]: v for v in data["vectors"]}

    failures: list[str] = []

    print(f"action_ref_namespace_v0 runner (Python / algovoi-substrate)")
    print(f"vectors: {len(vectors)}, pair invariants: {len(data['pair_invariants'])}")
    print()

    # Per-vector validation
    for vid, v in vectors.items():
        # 1. canonicalise preimage
        jcs = canonicalize(v["preimage"])
        jcs_bytes = jcs.encode("utf-8") if isinstance(jcs, str) else jcs

        # 2. base64 of JCS bytes
        actual_b64 = base64.b64encode(jcs_bytes).decode("ascii")
        if actual_b64 != v["expected_jcs_bytes_b64"]:
            failures.append(f"{vid}: JCS bytes b64 mismatch")
            print(f"  {vid}: FAIL (b64 mismatch)")
            continue

        # 3. SHA-256 of JCS bytes
        digest = hashlib.sha256(jcs_bytes).hexdigest()
        if digest != v["expected_action_ref"]:
            failures.append(f"{vid}: SHA-256 mismatch")
            print(f"  {vid}: FAIL (SHA-256 mismatch)")
            continue

        # 4. cross-check via the substrate's action_ref primitive
        ar = action_ref(
            agent_id=v["preimage"]["agent_id"],
            action_type=v["preimage"]["action_type"],
            scope=v["preimage"]["scope"],
            timestamp_ms=v["preimage"]["timestamp_ms"],
        )
        if ar != v["expected_action_ref"]:
            failures.append(f"{vid}: action_ref() mismatch")
            print(f"  {vid}: FAIL (action_ref primitive mismatch)")
            continue

        print(f"  {vid}: PASS  scope={v['scope']!r}  digest={digest[:16]}...")

    print()

    # Pair invariants
    for pair in data["pair_invariants"]:
        left = vectors[pair["left"]]["expected_action_ref"]
        right = vectors[pair["right"]]["expected_action_ref"]
        if pair["type"] == "different_hash_from":
            if left == right:
                failures.append(f"{pair['id']}: pair invariant violated")
                print(f"  {pair['id']}: FAIL (digests collide)")
            else:
                print(f"  {pair['id']}: PASS  {pair['left']} != {pair['right']}")
        else:
            failures.append(f"{pair['id']}: unknown pair type {pair['type']!r}")

    print()
    if failures:
        print(f"FAILED: {len(failures)} issue(s)")
        for f in failures:
            print(f"  - {f}")
        return 1

    print(
        f"PASS: {len(vectors)} vectors + {len(data['pair_invariants'])} pair invariants "
        f"validated against algovoi-substrate."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
