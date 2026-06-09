"""
action_ref_exactly_once_v1 runner (Python).

Validates the 6 vectors + 5 pair invariants in action_ref_exactly_once_v1.json using
algovoi-substrate (>=0.3.0) on PyPI. Supersets action_ref_transactional_v0 — adds the
PENDING/COMMITTED/REVERSED lifecycle plus the SKIP-on-retry idempotency (`same_hash_as`)
and action_ref replay-binding (`different_hash_from`) invariants.

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

VECTORS_FILE = Path(__file__).parent / "action_ref_exactly_once_v1.json"


def main() -> int:
    data = json.loads(VECTORS_FILE.read_text(encoding="utf-8"))
    vectors = {v["vector_id"]: v for v in data["vectors"]}
    failures: list[str] = []

    print("action_ref_exactly_once_v1 runner (Python / algovoi-substrate)")
    print(f"vectors: {len(vectors)}, pair invariants: {len(data['pair_invariants'])}")
    print()

    for vid, v in vectors.items():
        canon = canonicalize(v["preimage"])
        canon_bytes = canon.encode("utf-8") if isinstance(canon, str) else canon
        actual_b64 = base64.b64encode(canon_bytes).decode("ascii")
        if actual_b64 != v["expected_jcs_bytes_b64"]:
            failures.append(f"{vid}: JCS bytes b64 mismatch")
            print(f"  {vid}: FAIL (b64 mismatch)")
            continue

        digest = hashlib.sha256(canon_bytes).hexdigest()

        if v["pair_group"] == "identity":
            expected, label = v["expected_action_ref"], "action_ref"
            recomputed = action_ref(
                v["preimage"]["agent_id"], v["preimage"]["action_type"],
                v["preimage"]["scope"], v["preimage"]["timestamp_ms"])
            if recomputed != expected:
                failures.append(f"{vid}: action_ref() primitive mismatch")
                print(f"  {vid}: FAIL (action_ref primitive)")
                continue
        else:
            expected, label = v["expected_transition_hash"], "transition_hash"
            recomputed = transition_hash(
                v["preimage"]["action_ref"], v["preimage"]["state"],
                v["preimage"]["transition_timestamp_ms"],
                v["preimage"]["authority_verified_at_ms"],
                v["preimage"]["revocation_check_at_ms"])
            if recomputed != expected:
                failures.append(f"{vid}: transition_hash() primitive mismatch")
                print(f"  {vid}: FAIL (transition_hash primitive)")
                continue

        if digest != expected:
            failures.append(f"{vid}: SHA-256 mismatch")
            print(f"  {vid}: FAIL (SHA-256 mismatch)")
            continue

        state_or_id = v["preimage"].get("state", "<identity>")
        print(f"  {vid}: PASS  {label} state={state_or_id!r:13} digest={digest[:16]}...")

    print()

    def _h(vid):
        v = vectors[vid]
        return v.get("expected_transition_hash") or v.get("expected_action_ref")

    for pair in data["pair_invariants"]:
        lh, rh = _h(pair["left"]), _h(pair["right"])
        if pair["type"] == "different_hash_from":
            if lh == rh:
                failures.append(f"{pair['id']}: different_hash_from violated (digests collide)")
                print(f"  {pair['id']}: FAIL (digests collide)")
            else:
                print(f"  {pair['id']}: PASS  {pair['left']} != {pair['right']}")
        elif pair["type"] == "same_hash_as":
            if lh != rh:
                failures.append(f"{pair['id']}: same_hash_as violated (digests differ)")
                print(f"  {pair['id']}: FAIL (digests differ)")
            else:
                print(f"  {pair['id']}: PASS  {pair['left']} == {pair['right']} (idempotent)")

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
