#!/usr/bin/env python3
"""
rfc9421_proxy_chain_v1 — GENUINELY RFC 9421-conformant proxy-chain fixture generator.

Companion to rfc9421_proxy_chain_v0, which was signed with the legacy
`algovoi-v0` signing base (lowercased @method, "created" carried as a covered
component, no trailing @signature-params line). v0 remains as the labelled
algovoi-v0 signing-base survival set.

THIS set (v1) is RFC 9421 §2.5 conformant:
  - @method is preserved (uppercase GET)
  - the covered-components list is ("@method" "@authority" "@path" "content-digest")
    — `created` is a SIGNATURE PARAMETER, never a covered component
  - the signing base ends with the "@signature-params" line carrying the
    post-label Signature-Input value verbatim

The conformant base is built with the published verifier's own
build_signing_base(mode="rfc9421"), so the fixture is byte-for-byte what a
conformant verifier reconstructs. Signed with the RFC 8032 §7.1 Test 1 seed
(deterministic — re-running this script reproduces identical bytes).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

# Use the published verifier's conformant base builder so the fixture matches
# what verify_request(mode="rfc9421") reconstructs.
_PKG = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "..", "algovoi-rfc9421-verifier", "python",
)
if os.path.isdir(_PKG):
    sys.path.insert(0, _PKG)

from algovoi_rfc9421_verifier.signing_base import build_signing_base  # noqa: E402
from nacl.signing import SigningKey  # noqa: E402

# RFC 8032 Section 7.1 Test 1 — deterministic test vector
TEST_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
TEST_PUBKEY_HEX = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

# Fixed (deterministic) — reused from v0 so the ONLY differences between the two
# sets are the RFC 9421 conformance changes, not the timestamp.
CREATED = 1778955520
METHOD = "GET"
AUTHORITY = "api.algovoi.co.uk"
PATH = "/compliance/attestation"
KEYID = "did:web:api.algovoi.co.uk"
ENDPOINT = "https://api.algovoi.co.uk/compliance/attestation"

# RFC 9530 content-digest for an empty GET body
_CD_B64 = base64.b64encode(hashlib.sha256(b"").digest()).decode("ascii")
CONTENT_DIGEST = f"sha-256=:{_CD_B64}:"

# RFC 9421 conformant covered-components list — `created` is a PARAMETER, not a
# component identifier (RFC 9421 has no @created derived component).
COVERED = ["@method", "@authority", "@path", "content-digest"]
COVERED_INNER = "(" + " ".join(f'"{c}"' for c in COVERED) + ")"
SIG_PARAMS_RAW = (
    f'{COVERED_INNER};created={CREATED};keyid="{KEYID}";alg="ed25519"'
)
SIGNATURE_INPUT = f"sig={SIG_PARAMS_RAW}"


def _sign(base_str: str) -> str:
    sk = SigningKey(bytes.fromhex(TEST_SEED_HEX))
    sig = sk.sign(base_str.encode("utf-8")).signature
    return base64.b64encode(sig).decode("ascii")


def build_request_fixture() -> dict:
    signing_base = build_signing_base(
        COVERED,
        method=METHOD,
        authority=AUTHORITY,
        path=PATH,
        headers={"content-digest": CONTENT_DIGEST},
        parameters={"created": CREATED},
        mode="rfc9421",
        signature_params_raw=SIG_PARAMS_RAW,
    )
    sig_b64 = _sign(signing_base)
    return {
        "layer": "REQUEST",
        "description": (
            "RFC 9421-conformant signed GET request to "
            "api.algovoi.co.uk/compliance/attestation through a CF->nginx->FastAPI "
            "3-hop proxy chain. Conformant companion to rfc9421_proxy_chain_v0."
        ),
        "conformance": {
            "signing_base_mode": "rfc9421",
            "method_case_preserved": True,
            "created_is_parameter_not_component": True,
            "has_signature_params_line": True,
        },
        "spec_refs": {
            "rfc_9421": "https://www.rfc-editor.org/rfc/rfc9421",
            "rfc_9421_section": "2.5",
            "rfc_9530": "https://www.rfc-editor.org/rfc/rfc9530",
            "rfc_8032": "https://www.rfc-editor.org/rfc/rfc8032#section-7.1",
        },
        "keypair": {
            "seed_hex": TEST_SEED_HEX,
            "seed_source": "RFC 8032 Section 7.1 Test 1",
            "public_key_hex": TEST_PUBKEY_HEX,
        },
        "request": {
            "method": METHOD,
            "uri": ENDPOINT,
            "path": PATH,
            "authority": AUTHORITY,
            "headers": {
                "host": AUTHORITY,
                "content-digest": CONTENT_DIGEST,
                "signature-input": SIGNATURE_INPUT,
                "signature": f"sig=:{sig_b64}:",
            },
        },
        "signing": {
            "timestamp": CREATED,
            "covered_components": COVERED,
            "signature_params_raw": SIG_PARAMS_RAW,
            "signing_base": signing_base,
            "algorithm": "ed25519",
            "signature_value_b64": sig_b64,
        },
        "chain": {
            "description": "3-hop proxy chain: edge CDN -> reverse proxy -> application server",
            "hops": [
                {"hop": 1, "name": "Edge CDN", "role": "Edge proxy"},
                {"hop": 2, "name": "Reverse proxy", "role": "Reverse proxy"},
                {"hop": 3, "name": "Application server", "role": "Application server"},
            ],
        },
    }


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    req = build_request_fixture()
    # LF, trailing newline, stable key order — reproducible across platforms.
    with open(os.path.join(here, "request.fixture.json"), "w",
              encoding="utf-8", newline="\n") as f:
        json.dump(req, f, indent=2)
        f.write("\n")

    chain = {
        "fixture_name": "algovoi-proxy-chain-v1",
        "description": "RFC 9421 §2.5-conformant HTTP signature + RFC 9530 content-digest survival across a 3-hop proxy chain",
        "endpoint": ENDPOINT,
        "signing_base_mode": "rfc9421",
        "status": "ready_for_verification",
    }
    with open(os.path.join(here, "chain.fixture.json"), "w",
              encoding="utf-8", newline="\n") as f:
        json.dump(chain, f, indent=2)
        f.write("\n")

    print("[OK] wrote request.fixture.json + chain.fixture.json (rfc9421-conformant)")
    print(f"[OK] signature (b64): {req['signing']['signature_value_b64'][:48]}...")
    print("signing base:")
    print(req["signing"]["signing_base"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
