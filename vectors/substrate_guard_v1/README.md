# substrate_guard_v1

Conformance vectors for **algovoi-substrate-guard** — the deterministic input-bounds gate that runs
*before* canonicalization.

```
profile_ref = "sha256:" + SHA-256(JCS(profile))
guard(value, profile) -> accept, or reject with a named code
```

The resource edition of `adversarial_isolation`: where that set proves rejection of *malformed* input,
this proves fail-closed rejection of *well-formed but hostile* input (oversized, deeply nested, too many
keys, oversized strings/arrays, unsafe numbers). Every bound is a pure structural property of the parsed
value, so all implementations enforce it identically.

- `profile_ref_vectors` — the limits in force are content-addressed (pinnable).
- `accept` — control values (incl. at-the-limit) that MUST be accepted.
- `reject` — one isolated vector per bound, exceeding exactly one limit by one, that MUST reject with the
  named code: `REJECT_OVER_SIZE` / `REJECT_OVER_DEPTH` / `REJECT_TOO_MANY_KEYS` / `REJECT_OVER_ARRAY` /
  `REJECT_OVER_STRING` / `REJECT_OVER_NODES` / `REJECT_UNSAFE_NUMBER`.
- `invariants` — key-order invariance of the profile (JCS sorts), so `profile_ref` is construction-independent.

Default profile `guard-receipt-v1`: max_bytes 65536, max_depth 32, max_object_keys 256, max_array_length
1024, max_string_length 8192, max_total_nodes 4096, number_safety on.

Run: `pip install algovoi-substrate>=0.4.0 && python runner_python.py` (or `npm install @algovoi/substrate && node runner_node.js`).
