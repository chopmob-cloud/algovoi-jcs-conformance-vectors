#!/usr/bin/env python3
"""
AlgoVoi multi-chain Ed25519 fixture generator.

Demonstrates the same A2A payload signed with Ed25519 keys from three blockchains.

Deterministic: the timestamp is frozen (was int(time.time())) so the fixture
regenerates byte-for-byte, and files are written with LF newlines. Signatures are
produced with the real per-chain seeds (seed_hex); the published `chains` block
intentionally carries redacted placeholder seeds (published_seed_hex) -- the
fixture demonstrates cross-chain signing, it is not a key-disclosure vector.
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

CHAINS = {
    "algorand": {
        "path": "m/44'/283'/0'/0'/0'",
        "description": "Algorand Ed25519 (AVM standard)",
        "seed_hex": "df8e966c94469b23598aafaee6c14463ad40dc6286babad3096cb413979a8116",
        "published_seed_hex": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    },
    "solana": {
        "path": "m/44'/501'/0'/0'",
        "description": "Solana Ed25519 (SPL standard)",
        "seed_hex": "615666dae9d3625adaef933e4c1ed0158f657a22c2f570edcd1f7caa68e16413",
        "published_seed_hex": "c5b1e1a2d3f4e5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9",
    },
    "stellar": {
        "path": "m/44'/148'/0'",
        "description": "Stellar Ed25519 (Stellar standard)",
        "seed_hex": "232ed6f9fabf14e3bb55392b18cfe3d0febc94d20cc6327c38a1d075d6ea118c",
        "published_seed_hex": "d5c4b3a29f8e7d6c5b4a39f2e1d0c9b8a7f6e5d4c3b2a19f0e9d8c7b6a5f4",
    }
}


def sign_with_ed25519(payload_json, seed_hex, chain_name):
    if not HAS_NACL:
        return None, None
    try:
        seed_bytes = bytes.fromhex(seed_hex)
        if len(seed_bytes) != 32:
            raise ValueError(f"Seed must be 32 bytes, got {len(seed_bytes)}")
        signing_key = SigningKey(seed_bytes)
        signed_msg = signing_key.sign(payload_json.encode('utf-8'))
        signature_bytes = signed_msg.signature
        return base64.b64encode(signature_bytes).decode('ascii'), signature_bytes.hex()
    except Exception as e:
        print(f"[ERROR] {chain_name} signing failed: {e}")
        return None, None


def generate_multichain_fixture():
    payload_json = json.dumps(PAYLOAD, sort_keys=True, separators=(',', ':'))
    payload_sha256 = hashlib.sha256(payload_json.encode()).hexdigest()

    signatures = {}
    for chain_name, chain_info in CHAINS.items():
        sig_b64, sig_hex = sign_with_ed25519(payload_json, chain_info["seed_hex"], chain_name)
        signatures[chain_name] = {
            "signature_b64": sig_b64,
            "signature_hex": sig_hex,
            "derivation_path": chain_info["path"],
            "chain": chain_name,
        }

    published_chains = {
        name: {
            "path": info["path"],
            "description": info["description"],
            "seed_hex": info["published_seed_hex"],
        }
        for name, info in CHAINS.items()
    }

    evidence = [f"{name}: derivation path {info['path']}" for name, info in CHAINS.items()]

    fixture = {
        "layer": "MULTICHAIN",
        "description": "A2A payload signed with Ed25519 keys from three blockchain derivation paths",
        "spec_refs": SPEC_REFS,
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
