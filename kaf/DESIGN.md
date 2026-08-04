# Keystone Assurance Framework (KAF) v1

**An AlgoVoi original.** Internal design draft, 2026-08-02. Publication gated.
Every concept in this document is designed from first principles against the
primary standards (RFC 8785, RFC 9421, RFC 9530, the AVM ledger model) and our
own shipped code. Nothing herein derives from, references, or imports any
external conformance corpus design. External fixture sets we already validate
against (Envoys, Hippo) are one-way interop anchors only: we verify theirs, we
never copy into ours.

---

## 1. Position

We are not in a vector-count race. A list of vectors, however long, measures
nothing by itself: a vector only carries information when independent
implementations agree on it, when it was generated from a defined stratum of
the input space, when it was executed in a pinned runtime, and when the result
is evidence someone can re-verify. That is the game we play, because it is the
game we already win.

**Assurance, as KAF defines it, is the product of four axes:**

1. **Agreement** (how many genuinely independent implementations concur)
2. **Strata** (how much of the input space the generators provably reach)
3. **Cells** (how many runtime environments the verdicts hold in)
4. **Seal** (how strong and how deep the evidence chain is)

Corpus size is a dial on axis 2, reproducible on demand from a seed. It is not
an asset, and we do not count it.

## 2. What KAF certifies

KAF certifies the full deterministic-interop vertical that AlgoVoi ships,
which no other house owns end to end:

| Layer | Domain | Our shipped assets |
|-------|--------|--------------------|
| L1 | Canonicalization (RFC 8785 JCS) | conformance corpus, first-principles suite, mutation fuzz, 10-way differential substrate |
| L2 | HTTP message signatures (RFC 9421 + RFC 9530) | `algovoi-rfc9421-signer`, `algovoi-rfc9421-verifier` (py + ts, lock-step 0.3.3) |
| L3 | Key-credential binding | `algovoi-key-credential-binding` (PyPI 0.1.2, npm 0.1.1) |
| L4 | Settlement evidence (x402, AVM) | `algovoi-settlement-verify`, `algovoi-keystone-avm-proofpack`, `avm-proofpack` |
| X | Cross-layer composition | keystone gauntlets (5), composition chains (this design, section 9) |

A canonicalization-only corpus covers one row of this table.

## 3. Baseline, proven as of 2026-08-02

Everything below was validated on VM2 from registry state, recorded in
memory-graph claims 9799, 9800, 9801, and snapshotted in full to
`/opt/algovoi/corpus-snapshot-20260802/` after a full docker clean.

- Runner matrix: 114 runs, 0 failures, 0 findings (node 35/35; one declared
  optional-dep skip, `execution_ref_v1[node]`)
- verify_corpus 47/0, first_principles 11/11, mutation_fuzz 40 classes with
  0 escapes, adversarial gauntlet green
- 10-way differential substrate: full consensus at REQUIRE=10 on every
  agree/reject case (38/38), all 7 KAT anchors, 20 hazard cases mapped, all
  relational invariants and integrity gates green, twice
- All 5 keystone gauntlets green
- kcb conformance 10/10 from fresh registry installs
- External anchors: Envoys 5/5 verifiable positives, Hippo 2/2 composition
  vectors, byte-for-byte
- Standalone adversarial JCS property check 11/11

**Defects the framework has already caught in the wild** (this is the proof it
bites, and each one seeded a permanent regression class):

1. Node 18 WebCrypto global absent in module scope: every Ed25519
   verification failed and a bare catch reported "bad signature". Found by the
   cross-language matrix, fixed and shipped as verifier 0.3.3 on both
   registries. Also produced the eval-context rule in section 6.
2. kcb path-prefix scope bypass (CWE-863 class). Fixed, shipped, PyPI 0.1.2
   and npm 0.1.1, registry-verified.
3. Dependency-resolution drift: npm `^0.3.2` healed transitively by 0.3.3 but
   stale lockfiles pin the broken build. Now a named hazard class.
4. Ed25519 degenerate-input strictness split: noble (ZIP215) accepts an
   all-zeros probe that libsodium rejects. Open, becomes Hardened Profile v1
   work in section 8.

## 4. The four axes, made measurable

### 4.1 Agreement: Independent Agreement Quorum (IAQ)

IAQ is the number of genuinely independent implementations in byte-exact
agreement across the entire generated space. Independence means different
language, different author lineage, no shared canonicalization code, written
from the RFC text alone under a documented clean-room note per implementation.

- Current: **IAQ 10** (REQUIRE=10, full consensus, validated twice)
- Target: **IAQ 12** (two new clean-room implementations in languages outside
  the current set; candidates Zig, Swift, OCaml, Lua)

A corpus backed by one or two implementations has IAQ 1 or 2 regardless of how
many vectors it lists. IAQ is expensive to raise and impossible to fake, which
is why it is our headline number.

### 4.2 Strata: generative coverage, not curated lists

The input space is partitioned into named strata (section 7). Every vector is
(generator version, stratum, seed) addressable and reproducible. Coverage is
stated per stratum, and corpus volume at any size is derivable on demand.
The quality gate is the escape count: mutation classes on which any
implementation disagrees. Ours is 0 across 40 classes and stays 0 by gate.

### 4.3 Cells: verdicts are environment properties

The Node 18 finding proved that a verdict belongs to a cell
(implementation × runtime version × platform), not to an implementation.
KAF therefore executes in hermetic, digest-pinned containers (section 6) and
scores cell coverage explicitly.

### 4.4 Seal: evidence depth

Every battery run emits a signed, hash-chained receipt (section 5). Seal depth
is the length of the unbroken receipt chain. Depth accumulates in real time
and cannot be backdated, which makes it a moat that compounds while
competitors stand still.

**An assurance statement in KAF form:**
`KAF-A(iaq=10, strata=full catalog v1, cells=8, chain=n)` today, moving to
`KAF-A(iaq=12, strata=v2, cells=24+, chain=n+k)` through the roadmap.

## 5. The Keystone Seal (the stamp)

The stamp the user of our corpus sees, and the thing no other house can copy
without first trusting the exact stack under test.

**Sealed run receipt.** At the end of every battery run the harness emits a
receipt: a JCS-canonical JSON document (dogfooding L1) containing

- framework and corpus versions, generator versions and seeds
- the digest-pinned image digest of every cell that executed
- the verdict matrix digest and the sha256 tree root of all inputs/outputs
- the digest of the previous receipt (hash chain)
- timestamp and signer key id

The receipt is signed with **our own `algovoi-rfc9421-signer`** (Ed25519) and
verifies offline with the **published `algovoi-rfc9421-verifier`**. The
framework is self-hosting: the primitives being certified are the primitives
that seal the certification, and a third party can check the seal with one
command against public registry packages.

**Chain.** Receipts link backward, so the entire validation history becomes a
tamper-evident chain. The corpus already carries `_attestations/` from prior
runs; the Seal formalizes that practice, adds the signature and the chain.

**Anchor (optional, gated).** A receipt digest can be anchored to the AVM via
`keystone-avm-proofpack`, giving a public, portable, offline-verifiable
timestamp. That is an L4 asset we already ship and nobody else in this space
has.

**Verifier.** `kaf-verify`: one offline command that takes a receipt and the
snapshot tree, recomputes digests, checks the signature and the chain, and
prints the assurance statement. Anyone can audit us. That is the stamp.

## 6. Hermetic runtime cell matrix

- A cell is (language, runtime version, platform variant), executed in a
  container pinned by image digest, with vendored dependencies and **no
  network**.
- Initial catalog (about 24 cells): Node 18/20/22, Python 3.10/3.11/3.12/3.13,
  .NET 8, JDK 17/21, Go stable, Rust stable, Kotlin/JVM, plus glibc and musl
  variants where meaningful.
- **Real-module rule** (baked in from the Node 18 investigation): runners
  execute as real program files, never through REPL or eval contexts, because
  eval contexts inject globals that mask environment defects.
- Cell image digests are recorded in the sealed receipt, so a verdict is
  always attributable to an exact environment.
- VM2 docker was cleaned today specifically to host this matrix from zero.

## 7. Generative strata engine

Named strata, each with a deterministic seeded generator and a stated
coverage claim:

- IEEE-754 fences: subnormals, exponent boundaries, shortest-round-trip
  forms, minus zero, the 2^53 integer fence
- Number surface forms: exponent notation, precision extremes, signed zero
- UTF-16 surrogates: lone, paired, astral plane, combining sequences
- String pathologies: non-shortest-form UTF-8 at ingestion boundaries,
  control characters, escape ambiguities
- Structure: key-order permutations, deep nesting, width extremes,
  duplicate keys
- Cross-stratum products (number-in-key, surrogate-in-key, and so on)

Properties:

- (generator version, seed) fully determines the corpus; the corpus digest is
  reproducible and goes into the sealed receipt
- Mutation classes carry the zero-escape gate
- **Minimizer:** any disagreement anywhere shrinks automatically to a minimal
  reproducer, which becomes a permanent named regression vector. Real-bug
  archaeology is how the corpus grows teeth, and it cannot be copied without
  having found the bugs.

## 8. Hardened Profile v1 (security semantics)

The class the vector-count camp does not touch: what a secure implementation
must **reject**. One spec, enforced by default in our packages, with vectors
for every rule and 10-way consensus on the rejections.

- Crypto degenerate inputs: small-order and identity Ed25519 points, all-zero
  signatures, non-canonical scalars (s >= L), the ZIP215 versus cofactored
  divergence stated and pinned (closes the open finding, ships as verifier
  0.3.4 or 0.4.0 in lock-step)
- L1: duplicate-key rejection, lone-surrogate policy, non-shortest UTF-8 at
  boundaries, numeric normalization proofs
- L2: covered-component downgrade resistance, algorithm confusion refusal,
  created/expires windows, nonce and keyid binding, signature-params splice
  resistance
- L3: scope boundary semantics (the CWE-863 class we already found and fixed,
  generalized)
- L4: replay resistance, confirmed-round floors, evidence splice and
  cross-chain confusion rejection

## 9. Composition chains (the full vertical)

End-to-end vectors that thread all four layers: canonicalize, sign, bind the
key credential, settle, verify the evidence offline. At every junction an
adversarial variant attempts a cross-layer splice (valid L1 payload under a
forged L2 signature, valid L2 signature bound to the wrong L3 credential,
valid L3 binding replayed at L4, and the full taxonomy to be enumerated).
The 5 keystone gauntlets are the prototypes; KAF formalizes them into chain
classes executed across the cell matrix. A cross-layer attack taxonomy of
this shape does not exist elsewhere because nobody else ships all four layers.

## 10. Governance

- **Originality charter.** Vectors are generated from RFC text and our
  generators only. No external corpus is ever imported. External fixture sets
  remain one-way anchors. Each release records a statement of independence.
- **Freeze ritual.** Before any framework change: full battery green, docker
  clean, full snapshot to VM2 with checksums and manifest (performed today,
  this is P0 and it is now the standing rule).
- **Evidence discipline.** Every green is a memory-graph claim with an
  evidence command, and every executed phase is sealed into a receipt (P6).
- **Publication gate.** Unchanged and non-overridable. Nothing is pushed,
  published, or anchored without explicit per-action approval.

## 11. Why 50 houses cannot follow

| Pillar | Cost to replicate |
|--------|-------------------|
| IAQ 10 going on 12 | Ten-plus clean-room implementations is engineering breadth measured in years, and shared-code shortcuts are detectable |
| Real-bug archaeology | Regression classes come from defects you had to find in the wild first |
| Runtime cell matrix | Infrastructure plus the discipline of digest pinning and offline execution |
| Full L1-L4 vertical | Requires shipping signer, verifier, binding, and settlement stacks on public registries, which we already did |
| Self-hosting Seal | Sealing your results requires a signing stack you trust; for everyone else, that stack is the thing under test |
| Chain depth | Receipts compound with time and cannot be backdated. Every week they wait, the moat deepens |

## 12. Phases: executed vs intended

**Source-of-truth rule.** The sealed receipts in `kaf/receipts/` define the
canonical phase numbering. Their `run.purpose` fields are inside the signed bytes
and cannot be re-labelled. Every document (this file, `README.md`,
`kaf/README.md`) MUST match them. The original 2026-08-02 draft numbering
(P2=seal, P5=IAQ-12, P6=chains, P7=ledger) was superseded during execution and is
retained only in git history; do not cite it.

**Executed and sealed (live — the canonical P1-P6).** Each phase ends with the
full battery green locally (harness, not inspection), a snapshot, and a sealed
receipt. Chain head at time of writing: count 18, `4921dfe0...`.

- **P0, done 2026-08-02:** baseline 100%, VM2 docker cleaned, full snapshot with
  checksums and manifest (the genesis anchor, `kaf/MANIFEST.txt`).
- **P1, hermetic cell matrix** (`v3p1a`): 20-cell digest-pinned catalog, offline
  runner contract, network canary, real-module rule. Verdicts attributable to
  image digests.
- **P2, published-package cells** (`v3p2a`): the conformance run against the
  *published* PyPI/npm packages, catalog-anchored with an in-cell canary,
  byte-for-byte.
- **P3, differential rejection consensus** (`v3p3a`): degenerate-input classes and
  small-order rejection, with **10-way consensus on every rejection** across ten
  independent implementations.
- **P4, strata blast** (`v3p4a`): formal stratum catalog, seeded generators,
  minimizer. Zero escapes; plan digest reproducible from the seed.
- **P5, L1-L4 composition chains** (`v3p5a`): the full vertical
  identity -> authority -> policy -> decision -> execution chains plus the junction
  / splice attack taxonomy, green across the matrix.
- **P6, the Keystone Seal + offline verification:** receipt schema, signer
  integration, hash chain, and `kaf_verify`. Sealing is the act that produces every
  P1-P5 receipt; `kaf_verify` re-proves the whole chain offline against the
  registry packages. This is why there is no separate "P6 receipt".

**Intended, not yet executed (future — do NOT number as P1-P6 until sealed).**

- **Clean-room implementation expansion (IAQ 10 -> 12):** two additional
  independent implementations. Gate: full agreement maintained across the grown
  corpus and all cells.
- **Proof ledger:** the receipt chain surfaced as a proof ledger, optional AVM
  anchoring via proofpack. Gate: anchored receipt round-trips offline
  verification. Publication of any of it stays gated.

## 13. Keeping this from drifting again

1. A phase number is claimed only once its run is **sealed into a receipt**; until
   then it stays in the "intended" list above.
2. When a receipt is sealed, its `run.purpose` is the authoritative phase label;
   sync this file and both READMEs to it in the same change.
3. No publication without explicit per-action approval; that gate is unchanged.

*Stamp: AlgoVoi. Design authored 2026-08-02. This document is the design of
record for the corpus and vector estate going forward.*
