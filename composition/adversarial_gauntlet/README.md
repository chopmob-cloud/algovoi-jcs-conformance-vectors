# Adversarial gauntlet — 8-impl fail-closed cross-validation

Most conformance corpora prove implementations **agree on valid inputs**. This
gauntlet proves the harder thing: **8 independent implementations all reject every
adversarial input, and accept the control, identically** — fail-closed parity.

It extends `adversarial_isolation_v1`'s **Claim 2 (rejection)** from the reference
implementation to **all 8 languages**: 8 impls × 12 vectors = **96 fail-closed
verdicts**. See [`ATTESTATION.md`](./ATTESTATION.md) for the measured result.

## Run

```bash
bash run_gauntlet.sh
```

Each runner is an independent reimplementation of the three substrate-1 checks —
`transition_preimage`, `action_ref`, `audit_chain` — with **no `algovoi` import**.
A runner prints one line per vector (`<id> <verdict> expect=<…> OK|MISMATCH`) and a
final `GAUNTLET <lang> <ok>/<total>`; `run_gauntlet.sh` aggregates all eight.

| Runner | Command |
|---|---|
| `gauntlet_python.py` | `python gauntlet_python.py <vectors.json>` |
| `gauntlet_node.cjs`  | `node gauntlet_node.cjs <vectors.json>` |
| `gauntlet_ruby.rb`   | `ruby gauntlet_ruby.rb <vectors.json>` |
| `gauntlet_php.php`    | `php gauntlet_php.php <vectors.json>` |
| `gauntlet_go.go`     | `GO111MODULE=off go run gauntlet_go.go <vectors.json>` |
| `rust/`              | `cargo +stable-x86_64-pc-windows-gnu run --release -- <vectors.json>` |
| `java/Runner.java`   | `javac -cp "libs/*" Runner.java && java -cp ".;libs/*" Runner <vectors.json>` |
| `dotnet/`            | `dotnet run -c Release -- <vectors.json>` |

## Why it matters

A single-implementation fork can publish a fixture and a `verify.py`. It cannot
show that eight independent implementations, in eight languages, all fail closed on
the same eleven attacks. That is a property of a cross-validated substrate, not of
a one-file conformance suite — and it is reproducible here, not asserted.

Apache-2.0. © AlgoVoi. Redistribution requires NOTICE attribution.
