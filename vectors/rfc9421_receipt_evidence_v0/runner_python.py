"""rfc9421_receipt_evidence_v0 runner (Python).

Re-validates the L2 receipt-evidence set straight from each vector's `input`, offline,
using a single public library (rfc8785) — no AlgoVoi code. Checks three things:

  1. JCS canonical bytes + content hash reproduce the published values.
  2. The conformance rule: key_source=='cache' MUST carry key_provenance.population_ref;
     absence is non_conformant (CACHE_WITHOUT_POPULATION_EVENT). The derived verdict MUST
     match each vector's published `expectation`.
  3. The chain rule: the resolver_to_cache_valid cache row points back to the resolver
     population event by content hash.

Usage:
    pip install rfc8785>=0.1.2
    python runner_python.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

import rfc8785


def _derive_verdict(inp: dict, policies: dict) -> tuple[str, str | None]:
    """Independent re-derivation of the conformance verdict from the receipt evidence.

    The allowlist is resolved from the verifier-side `policies` registry, never trusted
    from the receipt — a signer controlling the policy label cannot widen the allowlist.
    """
    ks = inp.get("key_source")
    prov = inp.get("key_provenance", {})
    if ks == "cache":
        if not prov.get("population_ref"):
            return "non_conformant", "CACHE_WITHOUT_POPULATION_EVENT"
    elif ks == "resolver":
        allowed = policies.get(prov.get("allowlist_policy_id"), {}).get("allowed_resolver_urls", [])
        if prov.get("resolver_url") not in allowed:
            return "non_conformant", "RESOLVER_OUTSIDE_ALLOWLIST"
    elif ks == "inline":
        if not (prov.get("pinned_key_digest") or prov.get("origin_attestation")):
            return "non_conformant", "INLINE_WITHOUT_ORIGIN_PROOF"
    return "conformant", None


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    doc = json.load(open(os.path.join(here, "rfc9421_receipt_evidence_v0.json"), encoding="utf-8"))
    failures = 0
    by_id: dict[str, dict] = {}

    for v in doc["vectors"]:
        by_id[v["vector_id"]] = v
        jcs = rfc8785.dumps(v["input"])
        b64 = base64.b64encode(jcs).decode("ascii")
        ch = "sha256:" + hashlib.sha256(jcs).hexdigest()
        bytes_ok = b64 == v["expected_jcs_bytes_b64"]
        hash_ok = ch == v["expected_content_hash"]

        verdict, code = _derive_verdict(v["input"], doc.get("policies", {}))
        verdict_ok = verdict == v["expectation"] and code == v.get("non_conformance_code")

        ok = bytes_ok and hash_ok and verdict_ok
        print(("PASS" if ok else "FAIL"), v["vector_id"],
              f"[{v['case']}]", "->", verdict,
              "" if ok else f"(bytes={bytes_ok} hash={hash_ok} verdict={verdict_ok})")
        failures += 0 if ok else 1

    # chain invariant: cache row points back to the resolver population event by content hash
    for ci in doc.get("chain_invariants", []):
        frm = by_id[ci["from_vector"]]
        tgt = by_id[ci["must_equal_vector"]]
        ref = frm["input"]["key_provenance"]["population_ref"]
        ok = ref == tgt["expected_content_hash"]
        print(("PASS" if ok else "FAIL"), "chain:" + ci["id"], "->", "linked" if ok else "BROKEN")
        failures += 0 if ok else 1

    print(f"\n{'ALL GREEN' if failures == 0 else str(failures) + ' FAILURE(S)'} "
          f"({len(doc['vectors'])} vectors, {len(doc.get('chain_invariants', []))} chain invariant)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
