#!/usr/bin/env python3
"""
AlgoVoi multi-chain Ed25519 fixture verifier.

Validates that the same A2A payload was signed with three Ed25519 keys assigned
to three BIP44 derivation paths (Algorand, Solana, Stellar).

Self-contained: every input comes from fixture.json. No key material is
hardcoded here. For each chain the verifier

  1. re-derives the public key from the published seed_hex and checks it
     matches the published public_key_hex,
  2. re-signs the canonical payload with that seed and byte-matches the
     published signature (determinism), and
  3. verifies the published signature against the published public key
     (the actual Ed25519 verification a downstream consumer would run).

The seeds are public RFC 8032 test keys (see fixture.json key_material_note);
they are published precisely so this verification needs nothing external.
"""

import hashlib
import json
import sys
import base64
from pathlib import Path as _Path
_HERE = _Path(__file__).resolve().parent  # fixtures resolve from the script, not the caller's cwd

try:
    from nacl.signing import SigningKey, VerifyKey
    HAS_NACL = True
except ImportError:
    HAS_NACL = False


def verify_chain(payload_json, sig_info, chain_pub, chain_name):
    """Verify one chain entirely from published fixture material."""
    seed_hex = chain_pub["seed_hex"]
    published_pub = chain_pub["public_key_hex"]
    expected_sig_b64 = sig_info["signature_b64"]
    try:
        signing_key = SigningKey(bytes.fromhex(seed_hex))
        derived_pub = signing_key.verify_key.encode().hex()
        if derived_pub != published_pub:
            print(f"[FAIL] {chain_name.upper():8} public key mismatch")
            return False

        payload_bytes = payload_json.encode('utf-8')
        derived_sig = signing_key.sign(payload_bytes).signature
        if base64.b64encode(derived_sig).decode('ascii') != expected_sig_b64:
            print(f"[FAIL] {chain_name.upper():8} signature byte mismatch")
            return False

        # Independent verification against the public key (not just re-signing).
        VerifyKey(bytes.fromhex(published_pub)).verify(
            payload_bytes, base64.b64decode(expected_sig_b64))

        print(f"[OK] {chain_name.upper():8} pubkey + signature byte-match + verify")
        return True
    except Exception as e:
        print(f"[ERROR] {chain_name} verification failed: {e}")
        return False


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

    print("=== AlgoVoi Multi-Chain Fixture Verifier ===")
    print()

    if not HAS_NACL:
        print("[ERROR] PyNaCl required: pip install PyNaCl")
        sys.exit(1)

    try:
        with open(_HERE / "fixture.json") as f:
            fixture = json.load(f)
        print("[OK] Loaded fixture.json")
    except Exception as e:
        print(f"[ERROR] Failed to load fixture.json: {e}")
        sys.exit(1)

    print()

    payload_json = fixture["payload_canonical_json"]
    payload_sha256 = fixture["payload_sha256"]

    print(f"A2A Payload: {len(payload_json)} bytes")
    print(f"Payload SHA-256: {payload_sha256}")
    print()

    # Verify the declared payload_sha256 pin (was printed but never checked).
    _actual = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    if payload_sha256 not in (_actual, "sha256:" + _actual):
        print(f"[FAIL] payload_sha256 mismatch: declared {payload_sha256} != sha256(payload) {_actual}")
        sys.exit(1)
    # Positive-work floor: an empty signatures map must not vacuously pass.
    if not fixture.get("signatures"):
        print("[FAIL] no signatures to verify (empty signatures map)")
        sys.exit(1)

    all_valid = True
    for chain_name, sig_info in fixture["signatures"].items():
        chain_pub = fixture["chains"][chain_name]
        all_valid = verify_chain(payload_json, sig_info, chain_pub, chain_name) and all_valid

    print()
    print("=== VERIFICATION COMPLETE ===")

    if all_valid:
        print("All three chains signed the same A2A payload authentically.")
        print("Wire-format is substrate-independent across Algorand, Solana, Stellar.")
        sys.exit(0)
    else:
        print("One or more signatures failed verification.")
        sys.exit(1)
