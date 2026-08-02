# Differential adversarial substrate — 10-way consensus attestation

**A novel, AlgoVoi-original security artifact.** Not a port of anyone else's
corpus and not a mutation-count exercise. It proves a property a
two-implementation corpus *cannot express*: that ten independent JCS
implementations, each using a different canonicalization library, reach the
**same verdict** on adversarial input — and it **maps every point where they
diverge** so the substrate layer can forbid those shapes by design.

## Why this is ours by construction

Mutation testing and differential testing are decades-old, general techniques —
no one owns them. What is ours is the *substrate*: ten independent
reimplementations in ten languages with ten distinct JCS libraries
(python/rfc8785, node/canonicalize, go/gowebpki-jcs, php inline RFC 8785,
ruby/json-canonicalization, java + kotlin/erdtman, rust/serde_jcs,
dotnet/Baqhub, elixir/jcs). A differential oracle over that substrate asks a
question a 2-impl design (reference + one recompute) literally cannot ask:
*do all ten agree, and where exactly do they split?*

## Three pillars (one framework)

1. **Differential N-way consensus oracle** (`differential_driver.py`)
   Every adversarial input is fed to all ten canon probes. Each probe parses the
   raw bytes with its native parser and canonicalizes with its own JCS library,
   emitting `h:<sha256>` or `R:<reason>`. The driver requires:
   - `agree`  → all ten emit the **same** hash (a hash-split or any rejection fails);
   - `reject` → all ten **reject** (any hash fails).
   A split is the novel security signal: an input one implementation **accepts**
   while another **rejects**, or that two implementations hash **differently** —
   a cross-implementation trust break invisible to a single- or dual-impl corpus.

2. **JCS canonicalization-hazard corpus** (`cases_hazard_v1.json`)
   Probes RFC 8785's genuinely divergent edges and **maps** where the ten split.
   We do not assert agreement here; we prove where the hazard is and gate it out
   of every preimage at the schema/substrate layer. "100% by design" means we
   forbid the dangerous shape *because we located it*, not by luck.

3. **Tier-semantic adversarial corpus** (`cases_tier_v1.json`)
   Real AlgoVoi L2/L3 preimages (decision_audit, guard_context, revocation_link,
   settlement) — same rules as the keystone/revocation/settlement gauntlets —
   each tested three ways with relational invariants verified across all ten:
   - canonical form → `agree`;
   - key-order-scrambled form → `same_as` canonical (order must not change the hash);
   - one-field-tampered form → `differs_from` canonical (tamper must change the hash).
   No single canonicalizer can be tricked into a key-order or tamper collision.

## Result (live-run 2026-08-02)

| Environment | Impls | agree/reject | relational | hazards mapped | Result |
|---|---|---|---|---|---|
| VM2 (Linux) pass 1 | **10/10** | 29/29 | 7/7 | 13 | FULL 10-WAY CONSENSUS |
| VM2 (Linux) pass 2 | **10/10** | 29/29 | 7/7 | 13 | FULL 10-WAY CONSENSUS |
| Local (Windows)    | 9/10 (no elixir toolchain) | 29/29 | 7/7 | 13 | FULL 9-WAY CONSENSUS |

Ten languages: python, node, go, php, ruby, java, rust, dotnet, kotlin, elixir.

## Hazard map → substrate rules (10-impl, VM2)

Each documented divergence becomes a mandatory substrate/schema rule so these
shapes never reach a preimage:

| Hazard | Divergence across the 10 | Substrate rule |
|---|---|---|
| integer > 2^53 | 3-way: python rejects; elixir/php keep exact; 7 round to a different value | large counters MUST be string-encoded |
| 30-digit integer | 4-way: php/python reject; elixir one hash; ruby another; 6 round | no unbounded integers in preimages |
| float `1.5`, `0.1` | php rejects; 9 serialize | no floats in preimages |
| exponent `1e3` | php rejects; 9 normalize | integers only, no exponent forms |
| `1e400` / `NaN` / `Infinity` | uniform reject, via 3 different mechanisms | non-finite / non-JSON numbers rejected everywhere |
| duplicate keys | 3-way: JVM langs error; elixir one hash; 5 last-wins | reject duplicate keys before hashing |
| decomposed vs precomposed Unicode | uniform hash per byte-form (visually-equal strings differ) | NFC-normalize identifiers before binding |
| lone surrogate | **6-way split** (3 distinct hashes + 3 reject modes) | reject unpaired surrogates before hashing |
| leading zero `01` | go/java/kotlin/dotnet accept + normalize; 6 reject | reject leading-zero numbers before hashing |

The lone-surrogate case alone produces **six** distinct behaviours across the
ten implementations — the sharpest illustration of why N-way (not 2-way)
consensus is the property that matters.

## Run

```
bash run_differential.sh
# VM2: PATH=/opt/dotnet:/opt/kotlinc/bin:$HOME/.cargo/bin:$PATH DOTNET_ROOT=/opt/dotnet bash run_differential.sh
```

Source-only in git; every implementation rebuilds from source (see `.gitignore`).
