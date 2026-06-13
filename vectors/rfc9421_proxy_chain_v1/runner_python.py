#!/usr/bin/env python3
"""
rfc9421_proxy_chain_v1 runner (Python).

Verifies the RFC 9421-CONFORMANT proxy-chain fixture using the published
`algovoi-rfc9421-verifier` package in its default (rfc9421) mode. Install with:
    pip install algovoi-rfc9421-verifier

Unlike v0 (which is verified in mode="algovoi-v0"), this set is verified with
the conformant default — @method case-preserved, `created` as a parameter, and
a trailing @signature-params line. The reconstructed signing base must be
byte-identical to the fixture's, and the Ed25519 signature must verify.
"""
from __future__ import annotations

import json
import os
import sys

# Allow running against the in-repo package when not pip-installed.
_PKG = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "..", "algovoi-rfc9421-verifier", "python",
)
if os.path.isdir(_PKG):
    sys.path.insert(0, _PKG)

from algovoi_rfc9421_verifier import verify_request  # noqa: E402


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "request.fixture.json"), encoding="utf-8") as f:
        fix = json.load(f)

    req = fix["request"]
    result = verify_request(
        method=req["method"],
        authority=req["authority"],
        path=req["path"],
        headers=req["headers"],
        body=b"",
        public_key=fix["keypair"]["public_key_hex"],
        mode="rfc9421",
    )

    if not result.valid:
        print("[FAIL] verify_request returned invalid:")
        for err in result.errors:
            print(f"  - {err}")
        return 1
    if result.signing_base != fix["signing"]["signing_base"]:
        print("[FAIL] signing base mismatch")
        print("--- verifier rebuilt ---")
        print(result.signing_base)
        print("--- fixture ---")
        print(fix["signing"]["signing_base"])
        return 1

    print("[OK] signing base byte-identical to fixture (rfc9421 conformant)")
    print("[OK] @method case-preserved, @signature-params line present")
    print("[OK] RFC 9530 content-digest verified")
    print("[OK] Ed25519 signature verified")
    print("PASS (Python: algovoi-rfc9421-verifier, mode=rfc9421)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
