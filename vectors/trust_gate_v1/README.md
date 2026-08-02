# trust_gate_v1 — trust-gate deny decision table

Behavioural conformance set (a decision table, **not** a JCS-hash set). It pins
the gateway trust-gate's allow/deny outcome for every `verdict × mode`
combination plus the fail-open-on-mode edges.

**Rule source (verbatim):** `gateway/app/routers/verify.py`

```
_TRUST_GATE_DENY = {
  "block_untrusted": {"UNTRUSTED"},
  "require_trusted": {"UNTRUSTED", "PROVISIONAL", "INSUFFICIENT_EVIDENCE"},
}
_trust_gate_blocks(mode, verdict):  off / None / unknown mode → never blocks
                                    (fail-open on the mode); else verdict ∈ deny set.
```

- **verdicts:** TRUSTED, PROVISIONAL, INSUFFICIENT_EVIDENCE, UNTRUSTED
- **modes:** off, block_untrusted, require_trusted (+ None / unknown → fail-open)
- **15 vectors:** the full 4×3 matrix + 3 fail-open edges (null mode, unknown mode, unknown verdict).

## Run

```
python runner_python.py trust_gate_v1.json          # reference (no algovoi import)
python generate.py                                  # regenerate from the rule
```

Cross-language fail-closed parity (8 impls) is attested by
`composition/keystone_gauntlet/run_trust_gate_gauntlet.sh` — 120/120.
