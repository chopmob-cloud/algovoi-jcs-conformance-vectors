"""
adversarial_isolation_v1 runner (Python / reference impl) — both claims.

  Claim 1 (bytes): every `input` canonicalises to input_jcs_bytes_b64 / input_content_sha256.
  Claim 2 (rejection PoR): the named substrate-1 check rejects every mutated input and ACCEPTS
  the control. This is the reference-implementation rejection proof — NOT an 8-lang byte claim.
  (The 8-language attestation covers Claim 1 only; see _attestations/2026-06-09-adversarial-isolation-v1.)

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

from algovoi_substrate import (
    canonicalize,
    transition_preimage,
    action_ref_object,
    verify_audit_chain,
    TransactionalError,
    ActionRefError,
    AuditChainError,
)

VECTORS_FILE = Path(__file__).parent / "adversarial_isolation_v1.json"

CHECKS = {
    "transition_preimage": (lambda o: transition_preimage(**o), TransactionalError),
    "action_ref": (lambda o: action_ref_object(**o), ActionRefError),
    "audit_chain": (lambda o: verify_audit_chain(o), AuditChainError),
}


def _canon_bytes(obj) -> bytes:
    c = canonicalize(obj)
    return c.encode("utf-8") if isinstance(c, str) else c


def main() -> int:
    data = json.loads(VECTORS_FILE.read_text(encoding="utf-8"))
    failures: list[str] = []
    claim1 = claim2 = 0

    print("adversarial_isolation_v1 runner (Python / algovoi-substrate)")
    print(f"vectors: {len(data['vectors'])}  (Claim 1 = bytes 8-lang; Claim 2 = reference-impl rejection PoR)")
    print()

    for v in data["vectors"]:
        vid, check = v["vector_id"], v["check"]
        obj = v["input"]

        # Claim 1 — input is byte-deterministic / reproducible.
        cb = _canon_bytes(obj)
        if base64.b64encode(cb).decode("ascii") != v["input_jcs_bytes_b64"]:
            failures.append(f"{vid}: Claim 1 JCS bytes mismatch")
            print(f"  {vid}: FAIL (bytes)")
            continue
        if hashlib.sha256(cb).hexdigest() != v["input_content_sha256"]:
            failures.append(f"{vid}: Claim 1 sha256 mismatch")
            print(f"  {vid}: FAIL (sha256)")
            continue
        claim1 += 1

        # Claim 2 — the named check rejects (reject) or accepts (control).
        fn, exc_type = CHECKS[check]
        if v["expectation"] == "reject":
            try:
                fn(obj)
            except Exception as e:  # noqa: BLE001 — raising IS the expected behaviour
                want = v.get("expected_error")
                if want and type(e).__name__ != want:
                    failures.append(f"{vid}: raised {type(e).__name__}, expected {want}")
                    print(f"  {vid}: FAIL (wrong error {type(e).__name__})")
                    continue
                claim2 += 1
                print(f"  {vid}: PASS  reject [{v['expected_rejection']['code']}] {check} -> {type(e).__name__}")
            else:
                failures.append(f"{vid}: check ACCEPTED an input marked reject (false-green)")
                print(f"  {vid}: FAIL (false-green — check accepted it)")
        else:  # control: must NOT raise
            try:
                fn(obj)
                claim2 += 1
                print(f"  {vid}: PASS  control accepted by {check}")
            except Exception as e:  # noqa: BLE001
                failures.append(f"{vid}: control was REJECTED by {check} ({type(e).__name__})")
                print(f"  {vid}: FAIL (control rejected)")

    print()
    if failures:
        print(f"FAILED: {len(failures)} issue(s)")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"PASS: Claim 1 {claim1}/{len(data['vectors'])} input bytes exact; "
          f"Claim 2 {claim2}/{len(data['vectors'])} rejection/acceptance correct (reference impl).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
