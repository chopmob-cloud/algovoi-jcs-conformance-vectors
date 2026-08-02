# Keystone L3 gauntlet — multi-implementation fail-closed attestation

**Vector set:** `keystone_decision_audit_v1` (2 positive + 4 negative + 2 invariant = 8 checks/impl)
**Rule:** `decision_audit_ref = "sha256:" + SHA-256(JCS({decision_ref, passport_credential_ref, mandate_ref, policy_bound_ref, [screen_binding_ref]}))`, `sha256:` ref-form enforced.

## Why this exists

The published corpus validates the L1 substrate across 8 implementations and the
`adversarial_gauntlet` closes fail-closed rejection (Claim 2) for the three
substrate-1 checks across 8 languages. The **L3 keystone tier** (decision-audit)
was validated by the reference implementation only. This gauntlet extends
fail-closed parity to the keystone tier: independent reimplementations, each
using a **different JCS library**, all accept every positive, fail-close on every
negative (policy-rotation, passport swap, screen omission, malformed ref), and
hold both invariants (screen presence is bound; malformed ref rejected).

## Result (live-run 2026-08-02)

| Implementation | JCS library | Verdicts | Platform |
|---|---|---|---|
| Python | `rfc8785` | 8/8 | local + VM2 |
| Node | `canonicalize` | 8/8 | local + VM2 |
| Go | `gowebpki/jcs` | 8/8 | local |
| PHP | inline RFC 8785 | 8/8 | local |
| Ruby | `json-canonicalization` | 8/8 | local |
| Java 17 | `erdtman/java-json-canonicalization` | 8/8 | local |
| Rust | `serde_jcs` | 8/8 | local |
| .NET 9 | `Baqhub.JsonCanonicalization` | 8/8 | local |

**TOTAL: 64/64 across 8 independent implementations (local); python + node also 16/16 on VM2.** All green.
Eight distinct JCS libraries agree on both positives and fail-close on every negative + invariant.

## Run

```
bash run_keystone_gauntlet.sh
python gauntlet_python.py ../../vectors/keystone_decision_audit_v1/keystone_decision_audit_v1.json
node   gauntlet_node.mjs   ../../vectors/keystone_decision_audit_v1/keystone_decision_audit_v1.json
go run gauntlet_go.go      ../../vectors/keystone_decision_audit_v1/keystone_decision_audit_v1.json
```

## guard_context (live-run 2026-08-02)

`keystone_guard_context_v1` (1 positive + 4 negative + 2 invariant = 7 checks/impl),
`guard_context_ref = "sha256:" + SHA-256(JCS({canon_version, type, guard_timestamp_ms,
policy_ref, mandate_ref, passport_credential_ref}))`, non-negative-integer timestamp
enforced. Same 8 implementations, each fail-closing on timestamp/ref tamper and the
two invariants (moment-distinctness; non-integer guard_timestamp_ms rejected):

**56/56 across 8 implementations (local).** Run: `bash run_guard_context_gauntlet.sh`.

The keystone L3 tier (both decision_audit and guard_context) is now fully 8-impl
fail-closed: **120/120** combined.

## Extension path

php, ruby, rust, java, dotnet each already have a proven JCS+SHA-256 runner in
`vectors/retention_chain_v1/`; adding them here is a mechanical port of
`decisionAuditRef` (same construction, different fields). `keystone_guard_context_v1`
follows the same pattern.
