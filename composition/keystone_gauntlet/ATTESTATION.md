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

**TOTAL: 24/24 local (3 impls), 16/16 VM2 (2 impls).** All green.

## Run

```
bash run_keystone_gauntlet.sh
python gauntlet_python.py ../../vectors/keystone_decision_audit_v1/keystone_decision_audit_v1.json
node   gauntlet_node.mjs   ../../vectors/keystone_decision_audit_v1/keystone_decision_audit_v1.json
go run gauntlet_go.go      ../../vectors/keystone_decision_audit_v1/keystone_decision_audit_v1.json
```

## Extension path

php, ruby, rust, java, dotnet each already have a proven JCS+SHA-256 runner in
`vectors/retention_chain_v1/`; adding them here is a mechanical port of
`decisionAuditRef` (same construction, different fields). `keystone_guard_context_v1`
follows the same pattern.
