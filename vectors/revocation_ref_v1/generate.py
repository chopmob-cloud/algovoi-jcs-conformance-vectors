#!/usr/bin/env python3
"""Generate revocation_ref_v1.json -- fail-closed revocation link + chain integrity.

Rule source: substrate2/src/substrate2/keystone_secure.py
  revocation_ref(subject_ref, revoked_at_ms, reason_code, issuer_did, prev_status,
                 new_status, seq, prev_revocation_ref=None)
    -> "sha256:" + SHA-256(JCS({canon_version,type,subject_ref,revoked_at_ms,
       reason_code,issuer_did,prev_status,new_status,seq,prev_revocation_ref}))
    with sha256: ref-form, non-negative-int ms/seq, closed reason/status enums,
    non-empty issuer_did enforced (fail-closed: a malformed revocation is rejected,
    never silently accepted).
  verify_revocation_chain(links): seq 0..n-1, each prev_revocation_ref == prior
    link's ref, genesis prev is None.

The generator computes expected refs with the AUTHORITATIVE substrate2 impl and
cross-checks a from-rules rfc8785 reimplementation; runners reimplement independently.

    pip install rfc8785 ; python generate.py
"""
from __future__ import annotations
import hashlib, json
from pathlib import Path
import rfc8785
import substrate2.keystone_secure as ks

REASONS = list(ks.REVOCATION_REASONS)
STATUS = list(ks.STATUS_VALUES)
SUBJ = "sha256:" + "a" * 64


def preimage(subject_ref, revoked_at_ms, reason_code, issuer_did, prev_status, new_status, seq, prev_revocation_ref):
    return {"canon_version": "jcs-rfc8785-v1", "type": "revocation_link", "subject_ref": subject_ref,
            "revoked_at_ms": revoked_at_ms, "reason_code": reason_code, "issuer_did": issuer_did,
            "prev_status": prev_status, "new_status": new_status, "seq": seq,
            "prev_revocation_ref": prev_revocation_ref}


def ref_of(pre):
    return "sha256:" + hashlib.sha256(rfc8785.dumps(pre)).hexdigest()


# genesis (seq 0, prev None) + link1 -- expected refs are authoritative (substrate2) AND from-rules.
g_pre = preimage(SUBJ, 1716490000000, "KEY_COMPROMISE", "did:algo:issuer1", "active", "revoked", 0, None)
g_ref = ref_of(g_pre)
assert g_ref == ks.revocation_ref(subject_ref=SUBJ, revoked_at_ms=1716490000000, reason_code="KEY_COMPROMISE",
                                  issuer_did="did:algo:issuer1", prev_status="active", new_status="revoked",
                                  seq=0, prev_revocation_ref=None), "genesis mismatch vs substrate2"
l1_pre = preimage(SUBJ, 1716490500000, "SUPERSEDED", "did:algo:issuer1", "revoked", "inactive", 1, g_ref)
l1_ref = ref_of(l1_pre)
assert l1_ref == ks.revocation_ref(subject_ref=SUBJ, revoked_at_ms=1716490500000, reason_code="SUPERSEDED",
                                   issuer_did="did:algo:issuer1", prev_status="revoked", new_status="inactive",
                                   seq=1, prev_revocation_ref=g_ref), "link1 mismatch vs substrate2"

FIELDS = ("subject_ref", "revoked_at_ms", "reason_code", "issuer_did", "prev_status", "new_status", "seq", "prev_revocation_ref")


def fields_of(pre):
    return {k: pre[k] for k in FIELDS}


vectors = [
    {"id": "rev-genesis", **fields_of(g_pre), "expected_revocation_ref": g_ref},
    {"id": "rev-link1", **fields_of(l1_pre), "expected_revocation_ref": l1_ref},
]

# fail-closed negatives: a malformed revocation MUST reject, never be accepted.
def neg(id_, family, **over):
    base = fields_of(g_pre).copy()
    base.update(over)
    return {"id": id_, "family": family, **base, "must": "reject"}


negatives = [
    neg("rev-neg-unknown-reason", "reason_code", reason_code="NOPE"),
    neg("rev-neg-unknown-prev-status", "prev_status", prev_status="banned"),
    neg("rev-neg-unknown-new-status", "new_status", new_status="banned"),
    neg("rev-neg-malformed-subject", "subject_ref", subject_ref="not-a-ref"),
    neg("rev-neg-string-ms", "revoked_at_ms", revoked_at_ms="1716490000000"),
    neg("rev-neg-bool-ms", "revoked_at_ms", revoked_at_ms=True),
    neg("rev-neg-negative-ms", "revoked_at_ms", revoked_at_ms=-1),
    neg("rev-neg-empty-issuer", "issuer_did", issuer_did=""),
    neg("rev-neg-malformed-prev-ref", "prev_revocation_ref", prev_revocation_ref="bad", seq=1),
]

# tamper: a forged claimed ref must not equal the recompute.
bad_ref = "sha256:" + ("b" + g_ref[8:])
tamper = [{"id": "rev-tamper-claimed", **fields_of(g_pre), "claimed_revocation_ref": bad_ref, "must": "differ"}]

# chain integrity: valid chain verifies; tampered/reordered/bad-genesis chains fail closed.
chain_valid = [{"id": "rev-chain-ok", "links": [g_pre, l1_pre]}]
broken = json.loads(json.dumps(l1_pre)); broken["prev_revocation_ref"] = "sha256:" + "c" * 64
seqbad = json.loads(json.dumps(g_pre)); seqbad["seq"] = 5
genesis_prev = json.loads(json.dumps(g_pre)); genesis_prev["prev_revocation_ref"] = SUBJ
chain_invalid = [
    {"id": "rev-chain-broken-link", "links": [g_pre, broken], "note": "prev_revocation_ref does not match prior link"},
    {"id": "rev-chain-wrong-seq", "links": [seqbad], "note": "seq must be 0..n-1"},
    {"id": "rev-chain-genesis-has-prev", "links": [genesis_prev], "note": "genesis prev_revocation_ref must be null"},
]

doc = {
    "set": "revocation_ref_v1", "schema_version": "1",
    "description": "Fail-closed revocation-link ref + hash-linked chain integrity. A malformed "
                   "revocation is rejected (fail-closed-critical), and a tampered/reordered chain fails to verify.",
    "rule_source": "substrate2/src/substrate2/keystone_secure.py revocation_ref / verify_revocation_chain",
    "reason_codes": REASONS, "status_values": STATUS,
    "vectors": vectors, "negatives": negatives, "tamper": tamper,
    "chain_valid": chain_valid, "chain_invalid": chain_invalid,
}
out = Path(__file__).parent / "revocation_ref_v1.json"
out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline="\n")
print(f"wrote {out.name} ({len(vectors)} pos, {len(negatives)} neg, {len(tamper)} tamper, "
      f"{len(chain_valid)} chain-ok, {len(chain_invalid)} chain-bad)")
