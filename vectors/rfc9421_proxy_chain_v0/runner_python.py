#!/usr/bin/env python3
"""
runner_python.py -- RFC 9421 + RFC 9530 cross-validation runner for the
rfc9421_proxy_chain_v0 fixture.

Uses the published `algovoi-rfc9421-verifier` PyPI package. Install with:
    pip install algovoi-rfc9421-verifier

Run from the directory containing request.fixture.json:
    python runner_python.py

Exit code 0 = PASS, 1 = FAIL.
"""

import json
import sys

from algovoi_rfc9421_verifier import verify_request


def main() -> int:
    with open("request.fixture.json", encoding="utf-8") as f:
        fix = json.load(f)

    req = fix["request"]
    result = verify_request(
        method=req["method"],
        authority=req["authority"],
        path=req["path"],
        headers=req["headers"],
        body=b"",
        public_key=fix["keypair"]["public_key_hex"],
        mode="algovoi-v0",
    )

    if not result.valid:
        print("[FAIL] verify_request returned invalid:")
        for err in result.errors:
            print(f"  - {err}")
        return 1
    if result.signing_base != fix["signing"]["signing_base"]:
        print("[FAIL] signing base mismatch")
        return 1

    print("[OK] signing base byte-identical to fixture")
    print("[OK] RFC 9530 content-digest verified")
    print("[OK] Ed25519 signature verified")
    print("PASS (Python: algovoi-rfc9421-verifier on PyNaCl)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
