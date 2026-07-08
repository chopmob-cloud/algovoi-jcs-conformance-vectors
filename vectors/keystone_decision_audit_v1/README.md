# keystone_decision_audit_v1

Open, content-addressed **decision-audit bindings** for the AlgoVoi keystone (RFC 8785 JCS + SHA-256).

```
decision_audit_ref = "sha256:" + SHA-256(JCS({decision_ref, passport_credential_ref, mandate_ref, policy_bound_ref[, screen_binding_ref]}))
```

Binds a keystone decision to the exact passport it was made for, the mandate it was checked against, the
policy snapshot in force (`policy_bound_ref`), and — when a compliance screen applied — the screen it
consumed. Each input is imported by hash. Rotating the policy, swapping the passport, or omitting the
screen diverges the ref; the decision becomes auditable instead of a black box.

Produced by `algovoi-keystone-secure-lite` (Apache-2.0, no signature). The commercial Keystone Secure
signs the same construction with Falcon-1024 into the Compliance Command Center posture tiers.

- **2 positives** (screened / non-screened), **4 negatives** (policy-rotation, passport-swap,
  screen-omission divergence; malformed-ref rejection), **2 invariants** (screen-distinctness,
  policy-binding).
- Runner imports only stdlib + `rfc8785`: `python runner_python.py`.
