#!/usr/bin/env python3
"""
AlgoVoi §3.8 byte-match validation receipt for CTEF v0.3.1 + APS v1 canonicalization.

Validates AlgoVoi's JCS canonicalizer against:
  - 4 CTEF v0.3.1 test vectors from agentgraph.co/.well-known/cte-test-vectors.json
  - 10 APS bilateral-delegation vectors from aeoess/agent-passport-system

Pass criteria: for every vector, the canonicalizer MUST produce byte-identical
output to the expected `canonical_bytes_*` field AND the SHA-256 hash of that
output MUST match the expected `canonical_sha256` field exactly.

Canonicalizer used: rfc8785 v0.1.4 (Pure-Python RFC 8785 implementation).
This is the same library AlgoVoi uses production-side in:
  - gateway/app/routers/mpp.py (MPP probe envelope canonicalization)
  - gateway/app/routers/public_resource.py (x402 v2 envelope)
  - gateway/app/services/audit_chain.py (audit-bundle content_hash)
  - shared/utils/jcs_canonical.py (the shared helper)

All four production callers reduce to: rfc8785.dumps(obj) → SHA-256 → lowercase hex.

Run:
  pip install rfc8785
  python verify.py

Exit code 0 = all 14 vectors byte-match; non-zero = drift detected.
"""
import hashlib
import json
import sys

import rfc8785


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonicalize(obj) -> bytes:
    """AlgoVoi's JCS canonicalization. Single-line wrapper around rfc8785."""
    return rfc8785.dumps(obj)


def check_vector(*, name: str, input_obj, expected_bytes: bytes, expected_sha256: str) -> dict:
    """Run one vector through the canonicalizer and return the result record."""
    actual_bytes = canonicalize(input_obj)
    actual_sha256 = sha256_hex(actual_bytes)
    bytes_match = actual_bytes == expected_bytes
    sha_match = actual_sha256 == expected_sha256
    return {
        "name": name,
        "actual_bytes_hex": actual_bytes.hex(),
        "actual_sha256": actual_sha256,
        "expected_sha256": expected_sha256,
        "bytes_match": bytes_match,
        "sha256_match": sha_match,
        "pass": bytes_match and sha_match,
    }


def main() -> int:
    print("=" * 70)
    print("AlgoVoi §3.8 byte-match validation receipt")
    print("Canonicalizer: rfc8785 v0.1.4 (Python, pure RFC 8785)")
    print("=" * 70)
    print()

    # ── CTEF v0.3.1 vectors ──
    ctef = json.load(open("ctef_vectors.json", encoding="utf-8"))
    ctef_vector_keys = [
        "envelope_vector",
        "verdict_vector",
        "scope_violation_vector",
        "composition_failure_vector",
    ]
    print(f"CTEF v{ctef['version']} ({ctef['spec']})")
    print(f"  Source: https://agentgraph.co/.well-known/cte-test-vectors.json")
    print(f"  Canonicalization rule: {ctef['contract']['canonicalization']}")
    print()

    results = []
    for vkey in ctef_vector_keys:
        v = ctef[vkey]
        expected_bytes = v["canonical_bytes_utf8"].encode("utf-8")
        r = check_vector(
            name=f"CTEF/{vkey}",
            input_obj=v["input_object"],
            expected_bytes=expected_bytes,
            expected_sha256=v["canonical_sha256"],
        )
        results.append(r)
        status = "PASS" if r["pass"] else "FAIL"
        print(f"  [{status}] {r['name']}")
        if not r["pass"]:
            print(f"         expected sha256: {r['expected_sha256']}")
            print(f"         actual   sha256: {r['actual_sha256']}")
            print(f"         bytes_match:     {r['bytes_match']}")

    print()

    # ── APS v1 vectors ──
    aps = json.load(open("aps_vectors.json", encoding="utf-8"))
    print(f"APS {aps['version']} ({aps['spec']})")
    print(f"  Source: aeoess/agent-passport-system/fixtures/bilateral-delegation/canonicalize-fixture-v1.json")
    print(f"  Canonicalization: {aps['canonicalization']}")
    print(f"  Generated: {aps['generated_at']}")
    print()

    for v in aps["vectors"]:
        expected_bytes = bytes.fromhex(v["canonical_bytes_hex"])
        r = check_vector(
            name=f"APS/{v['name']}",
            input_obj=v["input"],
            expected_bytes=expected_bytes,
            expected_sha256=v["canonical_sha256"],
        )
        results.append(r)
        status = "PASS" if r["pass"] else "FAIL"
        print(f"  [{status}] {r['name']}: {v['description'][:60]}")
        if not r["pass"]:
            print(f"         expected sha256: {r['expected_sha256']}")
            print(f"         actual   sha256: {r['actual_sha256']}")
            print(f"         bytes_match:     {r['bytes_match']}")

    # ── Summary ──
    passed = sum(1 for r in results if r["pass"])
    total = len(results)
    print()
    print("=" * 70)
    print(f"Summary: {passed}/{total} vectors byte-match")
    print("=" * 70)

    # Receipt artefact
    with open("receipt.json", "w", encoding="utf-8") as f:
        json.dump(
            {
                "implementor": "AlgoVoi (chopmob-cloud)",
                "did": "did:web:api.algovoi.co.uk",
                "canonicalizer": "rfc8785 v0.1.4",
                "language": "Python",
                "ctef_version": ctef["version"],
                "aps_version": aps["version"],
                "total_vectors": total,
                "passed_vectors": passed,
                "byte_match": passed == total,
                "results": results,
            },
            f,
            indent=2,
        )
    print()
    print(f"Receipt: receipt.json ({total} per-vector records)")

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
