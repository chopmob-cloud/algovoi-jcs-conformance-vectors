"""
action_ref_transactional_v0 runner (Python).

Validates the 8 vectors + 5 pair invariants in
action_ref_transactional_v0.json using algovoi-substrate (>=0.3.0) on PyPI.

Usage:
    pip install algovoi-substrate>=0.3.0
    python runner_python.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from algovoi_substrate import action_ref, transition_hash, canonicalize

VECTORS_FILE = Path(__file__).parent / "action_ref_transactional_v0.json"


def main() -> int:
    data = json.loads(VECTORS_FILE.read_text(encoding="utf-8"))
    vectors = {v["vector_id"]: v for v in data["vectors"]}

    failures: list[str] = []

    print("action_ref_transactional_v0 runner (Python / algovoi-substrate)")
    print(f"vectors: {len(vectors)}, pair invariants: {len(data['pair_invariants'])}")
    print()

    for vid, v in vectors.items():
        canon = canonicalize(v["preimage"])
        canon_bytes = (
            canon.encode("utf-8") if isinstance(canon, str) else canon
        )
        actual_b64 = base64.b64encode(canon_bytes).decode("ascii")
        if actual_b64 != v["expected_jcs_bytes_b64"]:
            failures.append(f"{vid}: JCS bytes b64 mismatch")
            print(f"  {vid}: FAIL (b64 mismatch)")
            continue

        digest = hashlib.sha256(canon_bytes).hexdigest()

        if v["pair_group"] == "identity":
            expected = v["expected_action_ref"]
            label = "action_ref"
            # Cross-check against the substrate's action_ref primitive
            recomputed = action_ref(
                v["preimage"]["agent_id"],
                v["preimage"]["action_type"],
                v["preimage"]["scope"],
                v["preimage"]["timestamp_ms"],
            )
            if recomputed != expected:
                failures.append(f"{vid}: action_ref() primitive mismatch")
                print(f"  {vid}: FAIL (action_ref primitive)")
                continue
        else:
            expected = v["expected_transition_hash"]
            label = "transition_hash"
            recomputed = transition_hash(
                v["preimage"]["action_ref"],
                v["preimage"]["state"],
                v["preimage"]["transition_timestamp_ms"],
                v["preimage"]["authority_verified_at_ms"],
                v["preimage"]["revocation_check_at_ms"],
            )
            if recomputed != expected:
                failures.append(f"{vid}: transition_hash() primitive mismatch")
                print(f"  {vid}: FAIL (transition_hash primitive)")
                continue

        if digest != expected:
            failures.append(f"{vid}: SHA-256 mismatch")
            print(f"  {vid}: FAIL (SHA-256 mismatch)")
            continue

        state_or_id = v["preimage"].get("state", "<identity>")
        print(f"  {vid}: PASS  {label} state={state_or_id!r:18} digest={digest[:16]}...")

    print()
    for pair in data["pair_invariants"]:
        left = vectors[pair["left"]]
        right = vectors[pair["right"]]
        l_hash = left.get("expected_transition_hash") or left.get("expected_action_ref")
        r_hash = right.get("expected_transition_hash") or right.get("expected_action_ref")
        if pair["type"] == "different_hash_from":
            if l_hash == r_hash:
                failures.append(f"{pair['id']}: pair invariant violated")
                print(f"  {pair['id']}: FAIL (digests collide)")
            else:
                print(f"  {pair['id']}: PASS  {pair['left']} != {pair['right']}")

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
