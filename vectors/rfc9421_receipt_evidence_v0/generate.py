"""rfc9421_receipt_evidence_v0 — generator.

Builds the L2 receipt-evidence (key-source provenance) proposal set that sits ON TOP of
the L1 signing-base reference `rfc9421_proxy_chain_v1`. The L1 message-signature result is
IMPORTED as a fixed anchor (signing_base_ref) and never redefined here: identical signature,
different verifier-evidence meaning depending on how the signing key became acceptable.

Trust base: a single public library (rfc8785). No AlgoVoi code is imported, so the canonical
bytes are reproducible by anyone. `python generate.py` rewrites the JSON deterministically;
`runner_python.py` re-validates it independently.

Layer boundary (per a2aproject/A2A#1829):
  L1 = the RFC 9421 §2.5 signing base (rfc9421_proxy_chain_v1) — proves the message.
  L2 = THIS set — proves how the signing key became acceptable (key_source provenance).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os

import rfc8785

HERE = os.path.dirname(os.path.abspath(__file__))

# --- the imported L1 anchor (rfc9421_proxy_chain_v1 / REQUEST), verbatim ---
SIGNING_BASE_REF = {
    "vector_set": "rfc9421_proxy_chain_v1",
    "vector": "REQUEST",
    "alg": "ed25519",
    "keyid": "did:web:api.algovoi.co.uk",
    "signature": "sig=:qWRuNCsCUyKO/9MNtGApDxeznFm+07DyK4zN6eF/mnRcrQ3IaRpQOjQxY6xetCL+588L02Ajd3RjUR9jGi2jBw==:",
}
# RFC 8032 Section 7.1 Test 1 public key (the L1 keypair), digested as the resolved key material
_PUBKEY_HEX = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
KEY_DIGEST = "sha256:" + hashlib.sha256(bytes.fromhex(_PUBKEY_HEX)).hexdigest()

# Verifier-side policy registry (out-of-band; resolved by the verifier, never trusted from the
# signer). A receipt references a policy by id; the verifier resolves the *allowed* set from
# here. The signer controlling the label cannot widen the allowlist.
POLICIES = {
    "policy:jwks-allowlist:v1": {
        "allowed_resolver_urls": ["https://api.algovoi.co.uk/.well-known/jwks.json"],
    },
}


def jcs(obj: dict) -> bytes:
    return rfc8785.dumps(obj)


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def content_hash(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def base_obj(key_source: str, key_provenance: dict) -> dict:
    return {
        "canon_version": "jcs-rfc8785-v1",
        "evidence_layer": "receipt-key-source-v0",
        "signing_base_ref": SIGNING_BASE_REF,
        "key_source": key_source,
        "key_provenance": key_provenance,
    }


def finalize(vector_id: str, case: str, expectation: str, reason: str, obj: dict) -> dict:
    cb = jcs(obj)
    return {
        "vector_id": vector_id,
        "case": case,
        "expectation": expectation,          # "conformant" | "non_conformant"
        "non_conformance_code": reason if expectation == "non_conformant" else None,
        "input": obj,
        "expected_jcs_bytes_b64": b64(cb),
        "expected_content_hash": content_hash(cb),
    }


def main() -> None:
    # CASE 1 (resolver_to_cache_valid): a resolver population event, then a cache receipt
    # that points back to it. Two rows, chain-linked.
    row_a_obj = base_obj("resolver", {
        "resolver_url": "https://api.algovoi.co.uk/.well-known/jwks.json",
        "allowlist_policy_id": "policy:jwks-allowlist:v1",
        "resolved_key_digest": KEY_DIGEST,
        "population_timestamp_ms": 1778955520000,
    })
    row_a = finalize("001-resolver-population-event", "resolver_to_cache_valid",
                     "conformant",
                     "key_source=resolver records the population event (url, policy, key digest, timestamp)",
                     row_a_obj)

    row_b_obj = base_obj("cache", {
        # pointer back to the audited population event (row A's content hash)
        "population_ref": row_a["expected_content_hash"],
    })
    row_b = finalize("002-cache-with-population-ref", "resolver_to_cache_valid",
                     "conformant",
                     "key_source=cache carries population_ref pointing back to an audited resolver event",
                     row_b_obj)

    # CASE 2 (cache_laundering_invalid): cache claim with NO population provenance.
    row_c_obj = base_obj("cache", {})  # no population_ref, no source/timestamp/digest
    row_c = finalize("003-cache-laundering", "cache_laundering_invalid",
                     "non_conformant",
                     "CACHE_WITHOUT_POPULATION_EVENT",
                     row_c_obj)

    # CASE 3 (inline_pinned_valid): inline/pinned key material, no network-resolution posture.
    row_d_obj = base_obj("inline", {"pinned_key_digest": KEY_DIGEST})
    row_d = finalize("004-inline-pinned", "inline_pinned_valid",
                     "conformant",
                     "key_source=inline carries a pinned key digest and no network-resolution trust posture",
                     row_d_obj)

    # CASE 4 (resolver_outside_allowlist_invalid): a resolver fetch whose URL is NOT in the
    # verifier's allowlist policy. The wire signature still verifies (same L1 anchor), but the
    # key-source evidence fails: the key was fetched from an un-sanctioned resolver.
    row_e_obj = base_obj("resolver", {
        "resolver_url": "https://keys.evil.example/.well-known/jwks.json",
        "allowlist_policy_id": "policy:jwks-allowlist:v1",
        "resolved_key_digest": KEY_DIGEST,
        "population_timestamp_ms": 1778955520000,
    })
    row_e = finalize("005-resolver-outside-allowlist", "resolver_outside_allowlist_invalid",
                     "non_conformant",
                     "RESOLVER_OUTSIDE_ALLOWLIST",
                     row_e_obj)

    # CASE 5 (inline_unproven_invalid): inline key with NO origin/pinning proof — the signer
    # controls both the key material and the source label, so a resolver-origin key can be
    # relabeled "inline". Without pinning/origin evidence the inline claim is trust theater.
    row_f_obj = base_obj("inline", {})  # no pinned_key_digest, no origin_attestation
    row_f = finalize("006-inline-unproven", "inline_unproven_invalid",
                     "non_conformant",
                     "INLINE_WITHOUT_ORIGIN_PROOF",
                     row_f_obj)

    doc = {
        "schema_version": "rfc9421-receipt-evidence-v0",
        "artefact_id": "rfc9421_receipt_evidence_v0",
        "set_class": "proposal_set",
        "in_cross_validated_total": False,
        "canonicalizer": "RFC 8785 (JCS); reproduced by the public `rfc8785` library, no AlgoVoi code",
        "canon_version": "jcs-rfc8785-v1",
        "license": "Apache-2.0",
        "imports": {
            "signing_base_set": "rfc9421_proxy_chain_v1",
            "signing_base_vector": "REQUEST",
            "signing_base_source_sha256": "7e5e8f1012eabd6aaae52b0ae4e77e4c8b0392077b620d2d944002a0531901e8",
            "note": "L1 result is imported as a fixed anchor (signing_base_ref), not redefined here.",
        },
        "anchored_to": {
            "ietf_id": "draft-hopley-x402-canonicalisation-jcs-v1",
            "ietf_id_url": "https://datatracker.ietf.org/doc/draft-hopley-x402-canonicalisation-jcs-v1/",
            "rfc_9421_section": "2.5 (signing base, imported via L1)",
            "spec_authorship": "AlgoVoi (Christopher Hopley)",
        },
        "layer_boundary": {
            "L1": "RFC 9421 §2.5 signing base (rfc9421_proxy_chain_v1) — proves the message",
            "L2": "this set — proves how the signing key became acceptable (key_source provenance)",
            "invariant": "identical L1 signature, different verifier-evidence meaning by key_source",
        },
        "verification_recipe": [
            "1. For each vector, JCS-canonicalise input with RFC 8785.",
            "2. base64-encode the JCS bytes; MUST equal expected_jcs_bytes_b64.",
            "3. SHA-256 the JCS bytes (prefixed 'sha256:'); MUST equal expected_content_hash.",
            "4. cache rule: key_source=='cache' MUST carry key_provenance.population_ref; absence => non_conformant (CACHE_WITHOUT_POPULATION_EVENT).",
            "5. resolver rule: key_source=='resolver' resolver_url MUST be in the verifier's policies[allowlist_policy_id].allowed_resolver_urls; absence => non_conformant (RESOLVER_OUTSIDE_ALLOWLIST). The allowlist is resolved verifier-side, never trusted from the receipt.",
            "6. inline rule: key_source=='inline' MUST carry key_provenance.pinned_key_digest OR origin_attestation; absence => non_conformant (INLINE_WITHOUT_ORIGIN_PROOF).",
            "7. Chain rule: case 'resolver_to_cache_valid' row 002 population_ref MUST equal row 001 expected_content_hash.",
        ],
        "policies": POLICIES,
        "conformance_rules": [
            {
                "id": "cache_requires_population_ref",
                "rule": "key_source=='cache' requires key_provenance.population_ref (sha256 pointer to a resolver population event).",
                "violation_code": "CACHE_WITHOUT_POPULATION_EVENT",
            },
            {
                "id": "resolver_requires_allowlist",
                "rule": "key_source=='resolver' requires resolver_url to be in the verifier-resolved allowlist for allowlist_policy_id; the allowlist is never trusted from the receipt itself.",
                "violation_code": "RESOLVER_OUTSIDE_ALLOWLIST",
            },
            {
                "id": "inline_requires_origin_proof",
                "rule": "key_source=='inline' requires key_provenance.pinned_key_digest or origin_attestation; a bare inline label is bypassable (a resolver-origin key relabeled inline).",
                "violation_code": "INLINE_WITHOUT_ORIGIN_PROOF",
            },
        ],
        "vectors": [row_a, row_b, row_c, row_d, row_e, row_f],
        "chain_invariants": [
            {
                "id": "resolver_to_cache_linkage",
                "description": "002 cache row points back to 001 resolver population event by content hash.",
                "from_vector": "002-cache-with-population-ref",
                "field": "input.key_provenance.population_ref",
                "must_equal_vector": "001-resolver-population-event",
                "must_equal_field": "expected_content_hash",
            },
        ],
    }

    out = os.path.join(HERE, "rfc9421_receipt_evidence_v0.json")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print("wrote", out)
    print("vectors:", len(doc["vectors"]))


if __name__ == "__main__":
    main()
