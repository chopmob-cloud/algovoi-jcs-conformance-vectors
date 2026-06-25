# governance_decision_v1

Conformance vectors for the **crewAI `GovernanceDecision` contract**
([crewAIInc/crewAI PR #6030](https://github.com/crewAIInc/crewAI/pull/6030),
`lib/crewai/src/crewai/governance/governance_decision.py`).

The contract defines five content-derived identifiers, each
`"sha256:" + SHA-256(RFC 8785 (JCS) canonical bytes of the preimage)`. The contract
mandates JCS explicitly: *"All hash fields MUST be computed over RFC 8785 (JCS) ...
`json.dumps(sort_keys=True)` is NOT JCS and diverges on Unicode and non-integer fields."*
These vectors are the conformance set for that requirement: real computed digests, reproduced
**byte-for-byte across Python and an independent Node implementation**, so two runtimes that
implement the contract agree on every identifier instead of leaving it to interpretation.

AlgoVoi provides the **conformance layer** (JCS + SHA-256 digest reproducibility). The
**contract schema is crewAI's**; the field sets below are taken from PR #6030.

## Constructions

```
params_hash           = "sha256:" + SHA-256(JCS(tool_params))
intent_digest         = "sha256:" + SHA-256(JCS({agent_id, tool, params_hash, target_state_digest}))
intent_ref            = "sha256:" + SHA-256(JCS({agent_id, tool, normalized_scope, intent_digest, idempotency_key}))
receipt_ref           = "sha256:" + SHA-256(JCS({agent_id, tool, normalized_scope, intent_digest, idempotency_key, issued_at}))
decision_context_hash = "sha256:" + SHA-256(JCS({agent_id, tool, params_hash, intent_digest, seq,
                          retrieved_policy_refs, policy_digest, credential_scope, credential_tier,
                          expires_at, revalidate_if}))
```

`intent_ref` is the stable cross-runtime join key (no timestamp): retries of the same authorized
intent produce the same hash. `receipt_ref` adds `issued_at` so distinct records are always
distinct. Inner digests are carried as their `"sha256:"`-prefixed strings in the next preimage.

## What the vectors cover

- **digest vectors** (`vectors`): 5 decisions (`allow`, `deny`, `require_approval`, `revise`, plus a
  Unicode-scope case) with all five constructions computed.
- **normalization vectors** (`normalization_vectors`): the exact JCS canonical bytes of each
  `intent_ref` preimage, so a verifier can check its canonicalizer, not just the final hash.
- **negative vectors** (`negative_vectors`): malformed decisions that the contract's
  `validate_governance_decision` route rules must reject (e.g. an `allow` with no `policy_refs`,
  a `deny` with no `reason`), with the expected rejection reason.
- **completeness vectors** (`contiguity_vectors`): the four `seq` / `GovernanceSeal` cases,
  because the two drop modes are not symmetric. `complete` (sealed 0..2) verifies; `mid-gap`
  (seq 1 dropped) is self-evident from the running count; `tail-sealed` (a dropped suffix) is
  caught only because the seal pins the total; `tail-unsealed` is the honest residual, a suffix
  drop with no seal looks whole from the held set alone and passes (closing it needs an external
  anchor, RFC 3161, not a per-record field).
- **keystone reference** (`keystone_reference`): the composability proof referenced from the
  contract's Composability section. The published keystone (`composition/keystone_v1`) recomputes a
  full decision chain end to end; a `GovernanceDecision`'s `intent_ref` is the per-decision anchor
  such a chain composes over, verifiable by another crew with no shared runtime.

## Run it

```
pip install algovoi-substrate>=0.4.0
python runner_python.py            # 44/44 PASS

npm install @algovoi/substrate
node runner_node.js                # 44/44 PASS (Node == Python)
```

A PASS in both, against the same published hashes, is the byte-for-byte parity proof.

## Acknowledgment

The framing of sealed completeness as a distinct conformance axis, and the asymmetry of the
two drop modes (a dropped tail cannot be self-diagnosed from the held set without the seal
total), was raised by [@vaaraio](https://github.com/vaaraio) on
[crewAIInc/crewAI#6030](https://github.com/crewAIInc/crewAI/pull/6030). The vectors here are
derived independently from the contract's `GovernanceSeal`; the observation that sharpened
this axis is his.
