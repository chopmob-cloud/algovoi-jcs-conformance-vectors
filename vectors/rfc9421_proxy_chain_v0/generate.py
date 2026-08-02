#!/usr/bin/env python3
"""
AlgoVoi proxy-chain validation fixture generator with authentic RFC 9421 signing.

Generates an RFC 9421-signed GET request to api.algovoi.co.uk through a 3-hop chain,
using the RFC 8032 Section 7.1 Test 1 keypair for deterministic reproducible
signatures.

Deterministic and offline: timestamps are frozen (were int(time.time())), the
upstream response is a frozen capture embedded as a literal (no live network call
during generation), and files are written with LF newlines. Re-running reproduces
all three committed fixtures byte-for-byte.
"""

import json
import hashlib
import base64
import sys

try:
    from nacl.signing import SigningKey
    HAS_NACL = True
except ImportError:
    HAS_NACL = False

ENDPOINT = "https://api.algovoi.co.uk/compliance/attestation"
METHOD = "GET"

# RFC 8032 Section 7.1 Test 1 — deterministic test vector
TEST_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
TEST_PUBKEY_HEX = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

# Frozen timestamps (were int(time.time()) / time.gmtime()) for byte-for-byte reproduction.
REQUEST_TIMESTAMP = 1778955520
RESPONSE_TIMESTAMP = 1778955521
GENERATED_AT = "2026-05-16 18:18:41 UTC"

# Frozen capture of the upstream response (was a live HTTP GET). Embedded as a
# literal so generation is offline and reproducible; the fixture records what the
# 3-hop chain returned at capture time, it is not re-fetched.
FROZEN_RESPONSE = {
    "status": 200,
    "headers": {
        "Date": "Sat, 16 May 2026 18:18:42 GMT",
        "Content-Type": "application/json",
        "Transfer-Encoding": "chunked",
        "Connection": "close",
        "Server": "cloudflare",
        "Nel": "{\"report_to\":\"cf-nel\",\"success_fraction\":0.0,\"max_age\":604800}",
        "Vary": "Accept-Encoding",
        "cache-control": "public, max-age=300",
        "x-trace-id": "9b80b883-69e6-468b-9a85-96394f82497a",
        "Strict-Transport-Security": "max-age=31536000; preload",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Report-To": "{\"group\":\"cf-nel\",\"max_age\":604800,\"endpoints\":[{\"url\":\"https://a.nel.cloudflare.com/report/v4?s=ftPCJ%2Fj%2B9Fq6Pr4YMMVNEG8vYPVkt5KBms%2FbRlY0pfUqKYhDn83gdHdAomf6VVZ8rq2aaDMTDntGCETDUyVICcZhTICuJ2yHkBX88b%2B0DzZv8h9T4N18A1rtzg%2F6A9jqvV6Tnw%3D%3D\"}]}",
        "cf-cache-status": "DYNAMIC",
        "CF-RAY": "9fcc62ec2f5cb134-MAN",
        "alt-svc": "h3=\":443\"; ma=86400"
    },
    "body_length": 5502,
    "body_sha256": "6539fd116bf9d0691bd4ce568e00985e51c27b6131575e82813d46024a348690",
    "timestamp": RESPONSE_TIMESTAMP
}


def create_signing_input(timestamp):
    """RFC 9421 Signature-Input header value (label prefix added by the caller)."""
    return (
        f'("@method" "@authority" "@path" "content-digest" "created");'
        f'created={timestamp};keyid="did:web:api.algovoi.co.uk";alg="ed25519"'
    )


def create_signature_base(method, authority, path, content_digest, created):
    lines = [
        f'"@method": {method.lower()}',
        f'"@authority": {authority.lower()}',
        f'"@path": {path}',
        f'"content-digest": {content_digest}',
        f'"created": {created}'
    ]
    return '\n'.join(lines)


def sign_with_ed25519(signing_string):
    if not HAS_NACL:
        return None, None
    try:
        signing_key = SigningKey(bytes.fromhex(TEST_SEED_HEX))
        signed_msg = signing_key.sign(signing_string.encode('utf-8'))
        sig = signed_msg.signature
        return base64.b64encode(sig).decode('ascii'), sig.hex()
    except Exception as e:
        print(f"[ERROR] Ed25519 signing failed: {e}")
        return None, None


def generate_request_fixture():
    timestamp = REQUEST_TIMESTAMP

    content_digest_sha256 = hashlib.sha256(b"").hexdigest()
    content_digest_b64 = base64.b64encode(bytes.fromhex(content_digest_sha256)).decode('ascii')
    content_digest_header = f"sha-256=:{content_digest_b64}:"

    signature_input = create_signing_input(timestamp)
    signing_base = create_signature_base(
        "get", "api.algovoi.co.uk", "/compliance/attestation",
        content_digest_header, timestamp,
    )
    signature_b64, signature_hex = sign_with_ed25519(signing_base)

    return {
        "layer": "REQUEST",
        "description": "RFC 9421-signed GET request to api.algovoi.co.uk/compliance/attestation",
        "keypair": {
            "seed_hex": TEST_SEED_HEX,
            "seed_source": "RFC 8032 Section 7.1 Test 1",
            "public_key_hex": TEST_PUBKEY_HEX
        },
        "request": {
            "method": METHOD,
            "uri": ENDPOINT,
            "path": "/compliance/attestation",
            "authority": "api.algovoi.co.uk",
            "headers": {
                "host": "api.algovoi.co.uk",
                "content-digest": content_digest_header,
                "signature-input": signature_input,
                "signature": f"sig=:{signature_b64}:"
            }
        },
        "signing": {
            "timestamp": timestamp,
            "signing_base": signing_base,
            "algorithm": "ed25519",
            "signature_value_b64": signature_b64,
            "signature_value_hex": signature_hex
        },
        "timestamp": timestamp,
        "chain": {
            "description": "3-hop proxy chain: edge CDN -> reverse proxy -> application server",
            "hops": [
                {"hop": 1, "name": "Edge CDN", "role": "Edge proxy"},
                {"hop": 2, "name": "Reverse proxy", "role": "Reverse proxy"},
                {"hop": 3, "name": "Application server", "role": "Application server"}
            ]
        }
    }


def generate_chain_fixture():
    return {
        "fixture_name": "algovoi-proxy-chain",
        "description": "RFC 9421 signature and content-digest survival through CF->nginx->FastAPI",
        "generated_at": GENERATED_AT,
        "target_endpoint": ENDPOINT
    }


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    if not HAS_NACL:
        print("[ERROR] PyNaCl required")
        sys.exit(1)

    with open("request.fixture.json", "w", encoding="utf-8", newline="\n") as f:
        json.dump(generate_request_fixture(), f, indent=2)
    with open("response.fixture.json", "w", encoding="utf-8", newline="\n") as f:
        json.dump(FROZEN_RESPONSE, f, indent=2)
    with open("chain.fixture.json", "w", encoding="utf-8", newline="\n") as f:
        json.dump(generate_chain_fixture(), f, indent=2)
    print("[OK] Written request/response/chain fixtures (deterministic, offline)")
