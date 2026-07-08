# keystone_guard_context_v1

Open, content-addressed **admission-gate context** for the AlgoVoi keystone (RFC 8785 JCS + SHA-256).

```
guard_context_ref = "sha256:" + SHA-256(JCS({canon_version, type, guard_timestamp_ms, policy_ref, mandate_ref, passport_credential_ref}))
```

Pins the exact policy, mandate, and passport the admission gate saw at an integer-millisecond moment, so
the guard decision is reproducible offline. Each ref input is imported by hash; `guard_timestamp_ms` is
an integer millisecond hashed directly (Substrate Rule 2 — no floating point, no RFC 3339 strings).
Changing the moment, the policy, the mandate, or the passport diverges the ref.

Produced by `algovoi-keystone-secure-lite` (Apache-2.0, no signature). The commercial Keystone Secure
signs the same construction with Falcon-1024 into the Compliance Command Center posture tiers.

- **1 positive**, **4 negatives** (timestamp-shift, passport-swap divergence; float-timestamp and
  malformed-ref rejection), **2 invariants** (moment-distinctness, integer-ms rule).
- Runner imports only stdlib + `rfc8785`: `python runner_python.py`.
