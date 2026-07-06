#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Christopher Hopley / AlgoVoi (chopmob-cloud). Contributed under Apache-2.0.
"""AlgoVoi reference validator for the x402 exact-SVM optional create-ATA (facilitator static path).

This is the reference that *defines* conformance for the optional idempotent
CreateAssociatedTokenAccount a client may prepend at instruction index 2 so a first-time
recipient can be paid without the transfer failing with ``InvalidAccountData``. The
``svm_create_ata_v0.json`` vectors are the byte-level cases this validator accepts / rejects.

Every field is pinned because the fee payer funds the account rent: an unpinned funder lets a
client grief the facilitator into rent-funding arbitrary ``(owner, mint)`` ATAs (x402 issue
#1020). The destination is *recomputed* from ``(payTo, token program, mint)`` rather than trusted
from ``account[1]``, which is what actually closes the rent-redirect.

Reason codes (returned on reject):
  create_ata_wrong_program           program id is not the ATA program
  create_ata_not_idempotent          instruction data is not the single ``0x01`` idempotent byte
  create_ata_account_count           account list length is not 6
  create_ata_funder_mismatch         account[0] is not the fee payer (the anti-griefing funder pin)
  create_ata_destination_mismatch    account[1] is not the ATA derived from (payTo, token prog, mint)
  create_ata_owner_mismatch          account[2] is not payTo
  create_ata_mint_mismatch           account[3] is not the mint
  create_ata_system_program          account[4] is not the System Program
  create_ata_token_program_mismatch  account[5] is not the transfer's token program
"""
from __future__ import annotations

ATA_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
SYSTEM_PROGRAM = "11111111111111111111111111111111"


def derive_ata(pay_to: str, token_program: str, mint: str) -> str:
    """The associated token account for ``pay_to`` under ``token_program`` for ``mint``.

    Seeds are ``[owner, token_program, mint]`` under the ATA program, so the same owner and mint
    land on a different address per token program (Token vs Token-2022) -- which is exactly why
    the token program is a pinned field, not an assumption."""
    from solders.pubkey import Pubkey  # solders is the only dependency
    ata, _bump = Pubkey.find_program_address(
        [bytes(Pubkey.from_string(pay_to)),
         bytes(Pubkey.from_string(token_program)),
         bytes(Pubkey.from_string(mint))],
        Pubkey.from_string(ATA_PROGRAM))
    return str(ata)


def validate_create_ata(instr: dict, *, pay_to: str, mint: str, token_program: str,
                        fee_payer: str) -> tuple[bool, str | None]:
    """Validate one candidate create-ATA instruction for a payment to ``(pay_to, mint)`` settled
    under ``token_program`` with ``fee_payer`` funding rent.

    ``instr`` is ``{"program_id": str, "data_hex": str, "accounts": [{"pubkey": str}, ...]}``.
    Returns ``(accepted, reason)``; ``accepted`` is True only when every pin holds, else
    ``reason`` names the first failed pin. A facilitator accepts at most one such instruction at
    index 2 and shifts ``TransferChecked`` to index 3."""
    accts = [a["pubkey"] for a in instr.get("accounts", [])]

    def at(i: int) -> str | None:
        return accts[i] if i < len(accts) else None

    if instr.get("program_id") != ATA_PROGRAM:
        return False, "create_ata_wrong_program"
    if instr.get("data_hex") != "01":
        return False, "create_ata_not_idempotent"
    if len(accts) != 6:
        return False, "create_ata_account_count"
    if at(0) != fee_payer:
        return False, "create_ata_funder_mismatch"
    if at(1) != derive_ata(pay_to, token_program, mint):
        return False, "create_ata_destination_mismatch"
    if at(2) != pay_to:
        return False, "create_ata_owner_mismatch"
    if at(3) != mint:
        return False, "create_ata_mint_mismatch"
    if at(4) != SYSTEM_PROGRAM:
        return False, "create_ata_system_program"
    if at(5) != token_program:
        return False, "create_ata_token_program_mismatch"
    return True, None


def _selfcheck(path: str = "svm_create_ata_v0.json") -> int:
    """Run the reference validator over the committed vectors and confirm each verdict."""
    import json
    d = json.loads(open(path, "rb").read().decode("utf-8"))
    ctx = d["context"]
    ok = True
    for fx in d["fixtures"]:
        accepted, reason = validate_create_ata(
            fx["instruction"], pay_to=ctx["payTo"], mint=ctx["payment_mint"],
            token_program=ctx["transfer_token_program"], fee_payer=ctx["fee_payer"])
        want = fx["expected_verdict"] == "ACCEPT"
        good = accepted == want
        ok = ok and good
        print(f"  {'PASS' if good else 'FAIL'}  {fx['id']}: "
              f"{'ACCEPT' if accepted else 'REJECT'}{'' if accepted else ' (' + str(reason) + ')'}")
    print("OK" if ok else "MISMATCH")
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    sys.exit(_selfcheck(*sys.argv[1:]))
