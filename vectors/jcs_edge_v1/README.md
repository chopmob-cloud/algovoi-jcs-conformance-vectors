# jcs_edge_v1

Conformance vectors for the RFC 8785 (JCS) canonicalisation edge cases that a naive
"sorted-keys JSON" serialiser gets wrong and that a single-implementation self-check
cannot catch. This is the set to run an implementation against before trusting it to
produce byte-identical canonical output cross-party.

## What it pins

- **UTF-8 generation (RFC 8785 section 3.2.4).** U+2028 and U+2029 (line and
  paragraph separators) are emitted as literal UTF-8 bytes (`e2 80 a8` / `e2 80 a9`),
  never as their six-character backslash-u escapes. Go's `encoding/json` escapes them
  even with `SetEscapeHTML(false)`; PHP's `json_encode` escapes them unless
  `JSON_UNESCAPED_LINE_TERMINATORS` is set. A conformant JCS serialiser does not.
- **Property ordering (section 3.2.3).** Object property names sort by their UTF-16
  code units, not by Unicode code point. A supplementary-plane key (U+1F600, a
  surrogate pair whose lead unit is 0xD83D) sorts *below* U+FFFF; code-point ordering
  would reverse them. Vector `003` encodes this divergence.
- **Number form (section 3.2.2.3 / ES6).** `1.0` and `1` canonicalise to the same
  bytes.
- **Mandatory escapes (section 3.2.2.2).** The short escapes for backspace, form
  feed, newline, carriage return and tab; the `\u00xx` form for other control
  characters; and literal solidus and `&` `<` `>` (JCS does not HTML-escape).

## Contents

10 vectors, 2 pair invariants. Each vector carries `preimage`, `expected_jcs_bytes_b64`
(base64 of the canonical UTF-8 bytes) and `expected_sha256`, so an implementation
checks itself against the bytes rather than trusting a description. The file is pure
ASCII: preimage strings use `\u` escapes, and the canonical bytes appear only as
base64, so no code page can mangle the fixtures.

Pair invariants: `1.0 == 1` (equal SHA-256), and the U+1F600 key precedes the U+FFFF
key in the canonical bytes (UTF-16, not code-point, ordering).

## Cross-implementation validation

Validated byte-for-byte across **ten independent JCS implementations** (Python
`rfc8785`, JavaScript `canonicalize`, Ruby `json-canonicalization`, Go `gowebpki/jcs`,
Java and Kotlin `erdtman/java-json-canonicalization`, .NET
`Baqhub.Packages.JsonCanonicalization`, Rust `serde_jcs`, Elixir `jcs`, and a stdlib
PHP implementation) -- 10 vectors x 10 implementations = 100/100 agreements. See
[`_attestations/2026-07-19-jcs-edge-v1-ten-impl.md`](../../_attestations/2026-07-19-jcs-edge-v1-ten-impl.md).

The run caught a real non-conformance in the corpus's own stdlib PHP serialiser (it
escaped U+2028 and did not fold `1.0` to `1`) and it was patched -- the PHP instance
of the same serialiser fix as
[a2a-go#368](https://github.com/a2aproject/a2a-go/pull/368). The other nine
implementations were conformant without modification. That is the point: a
conformant-looking serialiser can pass every self-test and still diverge until an
independent vector set recomputes the bytes.

## Run it

    pip install rfc8785 ; python runner_python.py
    php runner_php.php

`generate.py` reproduces `jcs_edge_v1.json` from the reference implementation.

## Licence

Apache-2.0 (see [LICENSE](./LICENSE)). Copyright 2026 AlgoVoi (chopmob@gmail.com).
Preserve the repository NOTICE attribution in any distribution.
