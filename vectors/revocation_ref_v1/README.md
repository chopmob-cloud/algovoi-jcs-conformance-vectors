# revocation_ref_v1 — fail-closed revocation link + chain integrity

Fail-closed-critical keystone tier. A `revocation_ref` content-addresses one link
of a hash-linked revocation chain; `verify_revocation_chain` checks the chain is
ordered and unbroken. Both fail **closed**: a malformed revocation is rejected,
never silently accepted, and a tampered/reordered chain does not verify.

**Rule source:** `substrate2/src/substrate2/keystone_secure.py` (`revocation_ref` /
`verify_revocation_chain`). Expected refs are computed with the authoritative
substrate2 implementation and cross-checked against a from-rules rfc8785 reimplementation.

```
revocation_ref = "sha256:" + SHA-256(JCS({canon_version, type, subject_ref,
    revoked_at_ms, reason_code, issuer_did, prev_status, new_status, seq,
    prev_revocation_ref}))
```
- `subject_ref`/`prev_revocation_ref`: `sha256:` ref (prev is null at genesis)
- `revoked_at_ms`/`seq`: non-negative integers (bool / float / string rejected)
- `reason_code` ∈ {USER_REQUESTED, COMPLIANCE_TRIGGERED, EXPIRED, KEY_COMPROMISE, SUPERSEDED, ADMIN}
- `prev_status`/`new_status` ∈ {active, suspended, revoked, inactive}
- **16 checks:** 2 positive + 9 fail-closed negatives + 1 tamper + 1 valid chain + 3 invalid chains.

## Run

```
python runner_python.py revocation_ref_v1.json     # reference (no algovoi import)
python generate.py                                 # regenerate (needs substrate2 + rfc8785)
```

8-impl cross-language fail-closed parity: `composition/keystone_gauntlet/run_revocation_gauntlet.sh` — 128/128.
