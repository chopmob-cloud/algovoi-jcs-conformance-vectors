#!/usr/bin/env python3
"""
AlgoVoi multi-chain Ed25519 fixture generator.

Demonstrates the same A2A payload signed with Ed25519 keys assigned to three
blockchain BIP44 derivation paths.

KEYS ARE PUBLIC TEST VECTORS. Each chain uses a distinct secret key drawn
verbatim from RFC 8032 section 7.1 (Test 1, Test 2, Test 3). These are the
world-published Ed25519 test seeds; they are NOT real accounts and control no
funds. Using them makes the fixture internally verifiable from published
material alone: the seed_hex in the `chains` block IS the seed that produced
each signature, and each derived public key is published alongside, so any
third party can reproduce every signature (and verify it) with only
fixture.json. There is no hidden or redacted key material anywhere in this
vector.

Deterministic: the timestamp is frozen so the fixture regenerates
byte-for-byte, and files are written with LF newlines.
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

TIMESTAMP = 1778955897  # frozen (was int(time.time())) for byte-for-byte reproduction

PAYLOAD = {
    "agent_id": "did:web:api.algovoi.co.uk",
    "capability": "pay_on_behalf",
    "resource": "https://api.algovoi.co.uk/mandate/pay",
    "scope": ["checkout", "refund"],
    "expiration": 1778959200,
    "nonce": "9b80b883-69e6-468b-9a85-96394f82497a"
}

SPEC_REFS = {
    "a2a_protocol": "https://github.com/a2aproject/A2A",
    "rfc_9421": "https://www.rfc-editor.org/rfc/rfc9421",
    "rfc_8032": "https://www.rfc-editor.org/rfc/rfc8032",
    "bip44": "https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki",
    "a2a_issue": "https://github.com/a2aproject/A2A/issues/1829"
}

# Each chain is assigned one RFC 8032 section 7.1 test secret key. Public,
# documented, distinct, and deliberately NOT real accounts.
CHAINS = {
    "algorand": {
        "path": "m/44'/283'/0'/0'/0'",
        "description": "Algorand Ed25519 (AVM standard)",
        "seed_source": "RFC 8032 section 7.1 Test 1 secret key",
        "seed_hex": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    },
    "solana": {
        "path": "m/44'/501'/0'/0'",
        "description": "Solana Ed25519 (SPL standard)",
        "seed_source": "RFC 8032 section 7.1 Test 2 secret key",
        "seed_hex": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    },
    "stellar": {
        "path": "m/44'/148'/0'",
        "description": "Stellar Ed25519 (Stellar standard)",
        "seed_source": "RFC 8032 section 7.1 Test 3 secret key",
        "seed_hex": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    }
}


def sign_with_ed25519(payload_json, seed_hex, chain_name):
    if not HAS_NACL:
        return None, None, None
    try:
        seed_bytes = bytes.fromhex(seed_hex)
        if len(seed_bytes) != 32:
            raise ValueError(f"Seed must be 32 bytes, got {len(seed_bytes)}")
        signing_key = SigningKey(seed_bytes)
        public_key_hex = signing_key.verify_key.encode().hex()
        signed_msg = signing_key.sign(payload_json.encode('utf-8'))
        signature_bytes = signed_msg.signature
        return (base64.b64encode(signature_bytes).decode('ascii'),
                signature_bytes.hex(), public_key_hex)
    except Exception as e:
        print(f"[ERROR] {chain_name} signing failed: {e}")
        return None, None, None


def generate_multichain_fixture():
    payload_json = json.dumps(PAYLOAD, sort_keys=True, separators=(',', ':'))
    payload_sha256 = hashlib.sha256(payload_json.encode()).hexdigest()

    signatures = {}
    published_chains = {}
    for chain_name, chain_info in CHAINS.items():
        sig_b64, sig_hex, pub_hex = sign_with_ed25519(
            payload_json, chain_info["seed_hex"], chain_name)
        signatures[chain_name] = {
            "signature_b64": sig_b64,
            "signature_hex": sig_hex,
            "derivation_path": chain_info["path"],
            "chain": chain_name,
        }
        # The published block carries the SAME seed that produced the
        # signature (a public RFC 8032 test key) plus its derived public key,
        # so the fixture verifies from its own bytes with no external secret.
        published_chains[chain_name] = {
            "path": chain_info["path"],
            "description": chain_info["description"],
            "seed_source": chain_info["seed_source"],
            "seed_hex": chain_info["seed_hex"],
            "public_key_hex": pub_hex,
        }

    evidence = [f"{name}: derivation path {info['path']}" for name, info in CHAINS.items()]

    fixture = {
        "layer": "MULTICHAIN",
        "description": "A2A payload signed with Ed25519 keys from three blockchain derivation paths",
        "spec_refs": SPEC_REFS,
        "key_material_note": "All seed_hex values are public RFC 8032 section 7.1 test keys (Test 1/2/3). They are not real accounts and control no funds; they are published so the fixture is self-verifiable.",
        "payload": PAYLOAD,
        "payload_canonical_json": payload_json,
        "payload_sha256": payload_sha256,
        "timestamp": TIMESTAMP,
        "signatures": signatures,
        "chains": published_chains,
        "proof_of_substrate_independence": {
            "claim": "Same A2A payload is independently signable across Algorand, Solana, Stellar",
            "evidence": evidence,
            "implication": "Wire-format is substrate-independent; agents prove capability across chains without re-negotiation"
        }
    }
    return fixture


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    if not HAS_NACL:
        print("[ERROR] PyNaCl required")
        sys.exit(1)
    fixture = generate_multichain_fixture()
    with open("fixture.json", "w", encoding="utf-8", newline="\n") as f:
        json.dump(fixture, f, indent=2)
    with open("payload.json", "w", encoding="utf-8", newline="\n") as f:
        json.dump(PAYLOAD, f, indent=2)
    print("[OK] Written fixture.json + payload.json")
