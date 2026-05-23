# Schemas

JSON Schemas (draft 2020-12) for the AlgoVoi-authored substrate types.

## `compliance-receipt-v1.schema.json`

Schema for the categorical compliance screening receipt emitted by an
AlgoVoi-discipline screening provider at admission time and retained as part
of an audit chain under framework-bound retention obligations (UK MLR 2017,
EU AMLD5/6, MiCA Art. 80, AMLR Art. 56, DORA Art. 14).

Substrate references:
- [PR #2436](https://github.com/x402-foundation/x402/pull/2436) -- canonicalisation discipline (`canon_version` enforcement)
- [PR #2434](https://github.com/x402-foundation/x402/pull/2434) -- compliance-receipt-fixture (production-schema reference)
- [PR #2322](https://github.com/x402-foundation/x402/pull/2322) -- Compliance category proposal in x402-foundation/x402

Reference implementations that produce schema-valid receipts:
- Python: [`algovoi-substrate`](https://pypi.org/project/algovoi-substrate/)
  via `algovoi_substrate.build_compliance_receipt(...)`
- TypeScript: [`@algovoi/substrate`](https://www.npmjs.com/package/@algovoi/substrate)
  via `buildComplianceReceipt(...)`

## Examples

- [`examples/receipt-allow-uk-eu.json`](./examples/receipt-allow-uk-eu.json) -- standard ALLOW under UK + EU joint jurisdiction
- [`examples/receipt-refer-uk-sar-obligation.json`](./examples/receipt-refer-uk-sar-obligation.json) -- REFER under UK jurisdiction, triggering mandatory SAR obligation per POCA 2002 s.330
- [`examples/receipt-deny-sanctions.json`](./examples/receipt-deny-sanctions.json) -- DENY under sanctions match across UK + EU + US

All examples reference the schema via `$schema` so they validate on open in any
JSON-aware IDE that consumes the schemastore.org catalogue.

## Why the categorical outcome is load-bearing

A receipt that compresses the screening result to a score / tier
(`score: 75, tier: medium`) loses the regulatory distinction between
`REFER` and `DENY`:

- Under **UK POCA 2002 s.330**, a `REFER` carries a **mandatory** Suspicious
  Activity Report (SAR) obligation; the institution must file with the NCA.
- A `DENY` does not carry the SAR obligation in the same way -- the
  transaction is simply refused.
- A year-five supervisor reading retained bytes must be able to distinguish
  the two unambiguously. A score / tier projection cannot survive this
  distinction without an out-of-band lookup table.

The closed enum (`ALLOW` / `REFER` / `DENY`) in this schema is the
load-bearing primitive that downstream consumers (verifiers, auditors,
regulators) read directly from retained bytes.

## Usage

### IDE auto-validation

Any JSON file with `"$schema": "https://json.schemastore.org/algovoi-compliance-receipt-v1.json"` at the top will be auto-validated in:

- VSCode (with built-in JSON Schema support)
- IntelliJ / JetBrains IDEs
- Sublime Text (with LSP-json)
- Neovim (with `coc-json` or `jsonls`)

### Programmatic validation

```python
import json
import jsonschema

schema = json.load(open('compliance-receipt-v1.schema.json'))
receipt = json.load(open('examples/receipt-allow-uk-eu.json'))
jsonschema.validate(receipt, schema)  # raises ValidationError on failure
```

```typescript
import Ajv from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const ajv = new Ajv({ strict: false });
addFormats(ajv);
const validate = ajv.compile(schema);
const ok = validate(receipt);
if (!ok) console.error(validate.errors);
```

## schemastore.org submission

This schema is submitted to [schemastore.org](https://www.schemastore.org/)
under the file pattern `*-compliance-receipt-v1.json` so files matching that
pattern get the schema applied automatically.

The schema is also available at its `$id` URL:
`https://json.schemastore.org/algovoi-compliance-receipt-v1.json`

And as a stable URL from this repo:
`https://raw.githubusercontent.com/chopmob-cloud/algovoi-jcs-conformance-vectors/main/schemas/compliance-receipt-v1.schema.json`
