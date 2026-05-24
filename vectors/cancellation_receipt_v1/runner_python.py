"""
cancellation_receipt_v1 runner (Python).

Validates 8 vectors + 7 pair invariants + 3 chain invariants in
cancellation_receipt_v1.json using algovoi-substrate (>=0.3.0).

Anchors to IETF draft-hopley-x402-cancellation-receipt-00. Composes
with compliance_receipt_v1 (via mandate_ref), settlement_attestation_v1
(for recurring executions), and refund_receipt_v1 (PSD2 Art. 64
refund of revoked debits).

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

from algovoi_substrate import canonicalize

VECTORS_FILE = Path(__file__).parent / "cancellation_receipt_v1.json"


def main() -> int:
    data = json.loads(VECTORS_FILE.read_text(encoding="utf-8"))
    vectors = {v["vector_id"]: v for v in data["vectors"]}
    failures: list[str] = []

    print("cancellation_receipt_v1 runner (Python / algovoi-substrate)")
    print(
        f"vectors: {len(vectors)}, pair invariants: {len(data['pair_invariants'])}, "
        f"chain invariants: {len(data['chain_invariants'])}"
    )
    print()

    for vid, v in vectors.items():
        payload = v.get("receipt") or v.get("row")
        canon = canonicalize(payload)
        canon_bytes = canon.encode("utf-8") if isinstance(canon, str) else canon

        actual_b64 = base64.b64encode(canon_bytes).decode("ascii")
        if actual_b64 != v["expected_jcs_bytes_b64"]:
            failures.append(f"{vid}: JCS bytes b64 mismatch")
            print(f"  {vid}: FAIL (b64 mismatch)")
            continue

        digest = hashlib.sha256(canon_bytes).hexdigest()
        expected = v.get("expected_content_hash") or v.get("expected_row_content_hash")
        label = "content_hash" if "receipt" in v else "row_content_hash"

        if digest != expected:
            failures.append(f"{vid}: SHA-256 mismatch ({label})")
            print(f"  {vid}: FAIL (SHA-256 mismatch)")
            continue

        if "receipt" in v:
            r = v["receipt"]["cancellation_reason"]
            print(f"  {vid}: PASS  reason={r:22} {label[:14]}={digest[:16]}...")
        else:
            rn = v["row"]["row_number"]
            print(f"  {vid}: PASS  row={rn}     {label[:14]}={digest[:16]}...")

    print()
    for pair in data["pair_invariants"]:
        left = vectors[pair["left"]]["expected_content_hash"]
        right = vectors[pair["right"]]["expected_content_hash"]
        if pair["type"] == "different_hash_from":
            if left == right:
                failures.append(f"{pair['id']}: pair invariant violated")
                print(f"  {pair['id']}: FAIL")
            else:
                print(f"  {pair['id']}: PASS  {pair['left']} != {pair['right']}")

    print()
    for ch in data["chain_invariants"]:
        if ch["type"] == "field_equals":
            v = vectors[ch["vector"]]
            f = v
            for part in ch["field"].split("."):
                f = f[part]
            if f != ch["value"]:
                failures.append(f"{ch['id']}: field_equals violated")
                print(f"  {ch['id']}: FAIL")
            else:
                print(f"  {ch['id']}: PASS  {ch['field']} = expected")
        elif ch["type"] == "field_equals_other":
            lv = vectors[ch["left_vector"]]
            rv = vectors[ch["right_vector"]]
            lf = lv
            for part in ch["left_field"].split("."):
                lf = lf[part]
            rf = rv
            for part in ch["right_field"].split("."):
                rf = rf[part]
            if lf != rf:
                failures.append(f"{ch['id']}: linkage violated")
                print(f"  {ch['id']}: FAIL")
            else:
                print(
                    f"  {ch['id']}: PASS  {ch['left_vector']}.{ch['left_field']} = "
                    f"{ch['right_vector']}.{ch['right_field']}"
                )

    print()
    if failures:
        print(f"FAILED: {len(failures)} issue(s)")
        for f in failures:
            print(f"  - {f}")
        return 1

    print(
        f"PASS: {len(vectors)} vectors + {len(data['pair_invariants'])} pair invariants "
        f"+ {len(data['chain_invariants'])} chain invariants validated."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
