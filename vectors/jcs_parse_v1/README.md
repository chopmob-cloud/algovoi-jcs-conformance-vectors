# jcs_parse_v1

Parse-layer preconditions for RFC 8785 canonicalisation.

## Why this set exists

RFC 8785 canonicalises an **already-parsed** JSON value. Every other set in this
corpus therefore takes a parsed value as its input, and that makes one real defect
class impossible to express: duplicate object member names do not survive parsing.

```python
json.loads('{"a":1,"a":2}')   # -> {'a': 2}
```

By the time a canonicaliser sees the value, the duplicate is gone. It will happily
produce valid canonical bytes, and a signature over those bytes will verify, for a
document whose raw input never unambiguously said that. No canonicalisation vector
can catch this. The check belongs at parse, so this set carries **raw input bytes**
(base64) and pins the verdict a conforming parser must reach before any canonical
form is computed.

## Normative anchor

RFC 8259 section 4:

> The names within an object SHOULD be unique.
>
> An object whose names are all unique is interoperable in the sense that all
> software implementations receiving that object will agree on the name-value
> mappings. When the names within an object are not unique, the behavior of
> software that receives such an object is unpredictable. Many implementations
> report the last name/value pair only. Other implementations report an error or
> fail to parse the object, and some implementations report all of the name/value
> pairs, including duplicates.

Three different real behaviours. For a signed artifact that is handed to someone
else as evidence, "which parser opened it" must not change what the document says.

## Contents

3 accept vectors, 5 reject vectors, 1 reject code (`REJECT_DUPLICATE_MEMBER`).

The accept vectors are false-positive guards. Member names may legitimately repeat
across *different* objects, including sibling objects and successive array elements.
Uniqueness is scoped to one object, not to the document.

## Running

```bash
python runner_python.py jcs_parse_v1.json
```

Exit 0 when every vector reaches its stated verdict. The reference gate is a
`json.loads` `object_pairs_hook`, which is the only place the duplicate is still
visible.

## What the vectors discriminate

Each vector was mutation-tested against a wrong implementation, so none is
redundant:

| Wrong implementation | Caught by |
|---|---|
| Plain `json.loads`, no duplicate detection | all 5 reject vectors |
| Uniqueness tracked globally instead of per object | 2 of 3 accept vectors, falsely rejected |
| Only the top-level object checked | 2 of 5 reject vectors (`rj-duplicate-nested`, `rj-duplicate-in-array-element`) |

`rj-duplicate-identical-values` is deliberate: rejection is structural, not
value-based. A checker that de-duplicates by comparing values accepts that case and
establishes the code path that later accepts the divergent one.

`rj-duplicate-divergent-evidence` is the case that motivates the set. The raw bytes
carry two different values for one name, so a first-wins reader and a last-wins
reader disagree about what the record says, while a signature over the parsed value
still verifies.

## Regenerating

```bash
python generate.py
```

Deterministic. Inputs are fixed literals; no timestamps or randomness.

## Licence

Apache-2.0. Copyright 2026 AlgoVoi (chopmob@gmail.com).
