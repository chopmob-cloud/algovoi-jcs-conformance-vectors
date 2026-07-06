#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Christopher Hopley / AlgoVoi (chopmob-cloud). Contributed under Apache-2.0.
"""Working solution for x402 issue #1020: make a Solana recipient payment-ready with no
facilitator griefing surface.

The recipient (merchant) provisions their OWN associated token account, funded by their OWN key.
Because the signer is the account owner and pays their own rent, no facilitator or third party is
ever exposed to rent, so the ATA-sponsorship griefing vector (#1020) does not exist here: a key
can only ever create its own ATA. Run once per (wallet, mint) before accepting payments; the
instruction is idempotent and race-safe, so repeat calls and concurrent provisioning are no-ops.

This is the accepted shape: the rent is paid by the party that benefits (the recipient), not the
facilitator, which is why it avoids the objection that closed the facilitator-sponsorship PR
(#2798). The pinned instruction it emits conforms to the reference in this directory
(``reference_validator.py`` / ``svm_create_ata_v0.json``), read with the recipient as both funder
and owner.

Dependency: the Solana Python stack (``solders`` + ``spl``).

    python solution.py --mint <MINT> --rpc <RPC_URL>            # reads RECIPIENT_SECRET from env
"""
from __future__ import annotations

import base64
import json
import os
import urllib.request

ATA_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"


def _rpc(rpc_url: str, method: str, params: list):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(rpc_url, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310
        out = json.loads(resp.read())
    if "error" in out:
        raise RuntimeError(f"rpc error: {out['error']}")
    return out["result"]


def provision_recipient_ata(*, rpc_url: str, recipient_secret_base58: str, mint: str,
                            token_program: str | None = None) -> dict:
    """Ensure the recipient's ATA for ``mint`` exists, created and funded by the recipient's own key.

    Returns ``{"ata": str, "created": bool, "signature": str | None}``. Griefing-free: the owner is
    the funder and the signer, so no facilitator or third party is exposed to rent, and only the
    recipient's own ATA can ever be created."""
    from solders.hash import Hash
    from solders.keypair import Keypair
    from solders.message import Message
    from solders.pubkey import Pubkey
    from solders.transaction import Transaction
    from spl.token.constants import TOKEN_PROGRAM_ID
    from spl.token.instructions import (
        create_idempotent_associated_token_account, get_associated_token_address)

    kp = Keypair.from_base58_string(recipient_secret_base58)
    mint_pk = Pubkey.from_string(mint)
    tok = Pubkey.from_string(token_program) if token_program else TOKEN_PROGRAM_ID
    # owner == funder == signer == the recipient. No one else is ever the payer.
    ata = get_associated_token_address(kp.pubkey(), mint_pk, tok)
    info = _rpc(rpc_url, "getAccountInfo",
                [str(ata), {"encoding": "base64", "commitment": "confirmed"}])
    if (info or {}).get("value") is not None:
        return {"ata": str(ata), "created": False, "signature": None}
    ix = create_idempotent_associated_token_account(
        payer=kp.pubkey(), owner=kp.pubkey(), mint=mint_pk, token_program_id=tok)
    bh = Hash.from_string(
        _rpc(rpc_url, "getLatestBlockhash", [{"commitment": "confirmed"}])["value"]["blockhash"])
    tx = Transaction([kp], Message.new_with_blockhash([ix], kp.pubkey(), bh), bh)
    sig = _rpc(rpc_url, "sendTransaction",
               [base64.b64encode(bytes(tx)).decode(), {"encoding": "base64"}])
    return {"ata": str(ata), "created": True, "signature": sig}


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Provision the recipient's own ATA (griefing-free).")
    ap.add_argument("--mint", required=True)
    ap.add_argument("--rpc", required=True)
    ap.add_argument("--token-program", default=None)
    args = ap.parse_args()
    secret = os.environ.get("RECIPIENT_SECRET", "")
    if not secret:
        raise SystemExit("set RECIPIENT_SECRET (base58) in the environment")
    print(json.dumps(provision_recipient_ata(
        rpc_url=args.rpc, recipient_secret_base58=secret, mint=args.mint,
        token_program=args.token_program)))
