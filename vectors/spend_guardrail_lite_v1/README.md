# spend_guardrail_lite_v1

Open, content-addressed **pre-payment decisions** over the AlgoVoi substrate
(RFC 8785 JCS + SHA-256). The lite, Apache-2.0 origination layer for AlgoVoi Spend
Guardrail. One decision an agent platform makes before executing a payment, bound to
the agent, the spend authority, and the policy in force — each imported by hash:

```
guardrail_ref = "sha256:" + SHA-256(JCS({agent_ref, mandate_ref, policy_bound_ref, verdict}))
```

`verdict` is a closed enumeration **{ALLOW, DENY}**. `agent_ref` (a passport_ref),
`mandate_ref` (the spend authority), and `policy_bound_ref` (from
[`policy_binding_v1`](../policy_binding_v1/), the policy snapshot in force) are pinned
references. An ALLOW bound under policy P does **not** recompute under a rotated P′;
swapping the agent, the mandate, or the verdict diverges the `guardrail_ref`. Moves no funds.

Lite tier: no signature. The commercial Spend Guardrail adds Falcon-1024 signing on the
decision receipt and the full Agent Passport + Payment Mandate enforcement stack.

## Contents

10 checks: **2 positives** (ALLOW / DENY), **4 divergence negatives** (verdict /
policy-rotation / agent / mandate tamper), **2 rejection negatives** (invalid verdict,
malformed ref), **2 invariants** (verdict-distinctness, closed-enum). The
`policy_bound_ref` P / P′ are the published values from
[`policy_binding_v1`](../policy_binding_v1/) / `compliance_gate_lite_v1`, reused for
cross-set continuity.

## Validate

```bash
pip install "algovoi-substrate>=0.4.0"
python runner_python.py            # 10/10 PASS

npm install @algovoi/substrate
node runner_node.js                # 10/10 PASS (byte-for-byte parity with Python)
```

Reference implementations: [`algovoi-spend-guardrail-lite`](https://pypi.org/project/algovoi-spend-guardrail-lite/)
(PyPI) / [`@algovoi/spend-guardrail-lite`](https://www.npmjs.com/package/@algovoi/spend-guardrail-lite) (npm).
Anchors to `draft-hopley-x402-retention-chain`.
