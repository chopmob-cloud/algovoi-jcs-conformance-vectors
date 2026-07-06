<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Christopher Hopley / AlgoVoi (chopmob-cloud). Contributed under Apache-2.0.
-->
# x402 exact-SVM create-ATA facilitator conformance (AlgoVoi reference)

AlgoVoi-authored reference for the optional idempotent create-associated-token-account (create-ATA)
in the x402 exact-SVM payment scheme. This document is the normative surface; `reference_validator.py`
is the executable definition and `svm_create_ata_v0.json` is the byte-level conformance corpus.

Origin: the construction, the pin table, and the anti-griefing funder pin were authored by AlgoVoi
in x402 issue #2395 and are the design implemented in PR #2798; the griefing vector this closes is
x402 issue #1020.

## Problem

The exact-SVM client builds `TransferChecked` against the recipient's associated token account
without ensuring it exists. The first payment to any `payTo` / mint whose ATA has never been created
fails on-chain with `InstructionError: [.., InvalidAccountData]`. This cannot be fixed client-side
alone: the facilitator's static path pins `TransferChecked` at a fixed index, so a naively prepended
create-ATA is rejected as an unexpected instruction.

## Construction

The client prepends, at instruction index 2, a single `CreateAssociatedTokenAccountIdempotent`
(shifting `TransferChecked` to index 3) only when the destination ATA does not already exist. The
idempotent discriminant makes a lost race with a concurrent creation harmless. The facilitator
static path accepts at most one such instruction and pins every field.

### Pin table (facilitator static path, index 2)

| Field | Pin |
|---|---|
| program id | the ATA program (`ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`) |
| instruction data | exactly `0x01` (idempotent; the legacy non-idempotent `Create` is empty-data with 7 accounts) |
| account count | exactly 6 |
| `account[0]` funder | the fee payer |
| `account[1]` ata | the ATA derived from `(payTo, token program, mint)`, recomputed, not trusted |
| `account[2]` owner | `payTo` |
| `account[3]` mint | the payment mint |
| `account[4]` | the System Program |
| `account[5]` token program | the transfer's token program (a derivation seed, so it is pinned, not assumed) |

### Reason codes

`create_ata_wrong_program`, `create_ata_not_idempotent`, `create_ata_account_count`,
`create_ata_funder_mismatch`, `create_ata_destination_mismatch`, `create_ata_owner_mismatch`,
`create_ata_mint_mismatch`, `create_ata_system_program`, `create_ata_token_program_mismatch`.

## Security: the funder pin (x402 issue #1020)

The fee payer funds the account rent. An unpinned funder lets a client make the facilitator
rent-fund arbitrary `(owner, mint)` ATAs, draining the operator's SOL, which is the facilitator
ATA-sponsorship griefing vector in x402 issue #1020. Pinning `account[0]` to the fee payer and
recomputing `account[1]` from `(payTo, token program, mint)` (rather than trusting the supplied
address) together close it: the facilitator only ever sponsors the exact ATA of the recipient it is
paying, for an allowed mint. An implementation SHOULD additionally bound sponsorship out of band
(an allowed-mint set, a per-create rent cap, and an operator balance floor) so a flood of
first-time-recipient requests cannot drain the operator.

## Client discipline: conditional include

The client includes the create conditionally, one `getAccountInfo` on the destination ATA and the
prepend only when it is missing. Repeat payments keep the classic layout byte-identical, so a
facilitator that has not shipped this change still validates them exactly as before, and only a
first payment to a fresh ATA carries the create. Always-include would grow every payment and force
every facilitator to update in lockstep, so it is not the recommended shape.

## Conformance

- `reference_validator.py` -- `validate_create_ata(instr, pay_to, mint, token_program, fee_payer)`
  returns `(accepted, reason)`; it recomputes the destination ATA and pins the funder. Run
  `python reference_validator.py` to check it against the corpus.
- `svm_create_ata_v0.json` -- one positive and three negatives, each isolating a distinct pin.
- `verify.py` -- dependency-free recompute of the corpus verdicts from the pins.

## Licence

Apache-2.0. Copyright 2026 Christopher Hopley / AlgoVoi (chopmob-cloud).
