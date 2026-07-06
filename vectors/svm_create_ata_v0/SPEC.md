<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Christopher Hopley / AlgoVoi (chopmob-cloud). Contributed under Apache-2.0.
-->
# x402 exact-SVM create-ATA facilitator conformance (AlgoVoi reference)

AlgoVoi-authored reference for the optional idempotent create-associated-token-account (create-ATA)
in the x402 exact-SVM payment scheme. This document is the normative surface; `reference_validator.py`
is the executable definition and `svm_create_ata_v0.json` is the byte-level conformance corpus.

Origin: the construction, the pin table, and the anti-griefing funder pin were authored by AlgoVoi
in x402 issue #2395 and were implemented in PR #2798. x402 issue #1020 documents the ATA-sponsorship
griefing this addresses. The funder pin closes only the rent-redirect sub-vector; the rent-reclaim
vector that is #1020's canonical form is inherent to facilitator sponsorship and is closed not by
pinning but by recipient self-provisioning (below), which is the direction #1020 sanctions.

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

## Security: rent reclaim and the funder pin (x402 issue #1020)

The canonical griefing vector in x402 issue #1020 is rent reclaim. When the facilitator (the fee
payer) funds a recipient's ATA, the recipient owns that account, so it can close the account with
`closeAccount`, receive the rent lamports, and repeat with a fresh wallet or mint. This is inherent
to any facilitator-funded creation and is NOT closed by the pins below: pinning guarantees the
facilitator sponsors the exact ATA of the recipient it is paying, but it does nothing to stop that
recipient from closing the account and pocketing the rent.

The funder pin closes a different, narrower vector: rent redirect. An unpinned `account[0]` or an
untrusted `account[1]` would let a client make the facilitator rent-fund an arbitrary
`(owner, mint)` ATA rather than the one it is actually paying. Pinning `account[0]` to the fee payer
and recomputing `account[1]` from `(payTo, token program, mint)` (rather than trusting the supplied
address) closes redirect: the facilitator only ever sponsors the exact ATA of the recipient it is
paying, for an allowed mint. An implementation that still sponsors SHOULD bound it out of band (an
allowed-mint set, a per-create rent cap, an operator balance floor), but these only bound the drain
from a flood of first-time recipients; they do not close reclaim.

Because rent reclaim is inherent to facilitator sponsorship, the direction sanctioned in issue #1020
is that the facilitator does not sponsor at all: the recipient provisions their own ATA (next
section), which is the only shape that closes both redirect and reclaim.

## Client discipline: conditional include

The client includes the create conditionally, one `getAccountInfo` on the destination ATA and the
prepend only when it is missing. Repeat payments keep the classic layout byte-identical, so a
facilitator that has not shipped this change still validates them exactly as before, and only a
first payment to a fresh ATA carries the create. Always-include would grow every payment and force
every facilitator to update in lockstep, so it is not the recommended shape.

## Working solution: recipient provisioning (x402 issue #1020)

The griefing objection to facilitator sponsorship is answered by having the party that benefits
pay the rent. The recipient provisions their own ATA, funded by their own key, once per
`(wallet, mint)` before accepting payments. Because the owner is the funder and the signer, no
facilitator or third party is ever exposed to rent, and a key can only ever create its own ATA.
Closing the account only ever returns the recipient's own rent to the recipient, so neither the
rent-reclaim nor the rent-redirect vector of #1020 exists in this shape. The instruction it emits
conforms to the pin table above, read with the recipient as both funder and owner. `solution.py` is
a working reference: `provision_recipient_ata(rpc_url, recipient_secret_base58, mint, token_program=None)`,
idempotent and race-safe.

An equivalent shape nets the rent from the first payment, so a first-time recipient is provisioned
out of what they receive rather than needing SOL up front; the funding party is still the recipient,
not the facilitator.

## Conformance

- `reference_validator.py` -- `validate_create_ata(instr, pay_to, mint, token_program, fee_payer)`
  returns `(accepted, reason)`; it recomputes the destination ATA and pins the funder. Run
  `python reference_validator.py` to check it against the corpus.
- `svm_create_ata_v0.json` -- one positive and three negatives, each isolating a distinct pin.
- `verify.py` -- dependency-free recompute of the corpus verdicts from the pins.

## Licence

Apache-2.0. Copyright 2026 Christopher Hopley / AlgoVoi (chopmob-cloud).
