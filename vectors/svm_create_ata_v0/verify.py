#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Christopher Hopley / AlgoVoi (chopmob-cloud). Contributed under Apache-2.0.
"""Dependency-free verifier for the x402 create-ATA facilitator conformance fixtures.

Recomputes the facilitator's index-2 accept/reject verdict for each fixture purely
from the pinned assertions, and checks it against the fixture's declared verdict.
The fixtures are data, not a reference implementation: run your own facilitator's
static-path check against them, or run this to confirm the set is internally sound.

    python3 verify.py            # verifies svm_create_ata_v0.json in this dir
"""
import json, sys, base64
from pathlib import Path as _Path
_HERE = _Path(__file__).resolve().parent  # fixtures resolve from the script, not the caller's cwd

ATA_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
SYSTEM_PROGRAM = "11111111111111111111111111111111"

def evaluate(instr, ctx):
    """Return the ordered list of pin assertions this create-ATA instruction fails."""
    accts = [a["pubkey"] for a in instr["accounts"]]
    def at(i): return accts[i] if i < len(accts) else None
    fails = []
    if instr["program_id"] != ATA_PROGRAM:            fails.append("program == ATA program")
    if instr.get("data_hex", "") != "01":             fails.append("data == 0x01")
    if len(accts) != 6:                               fails.append("accounts length == 6")
    if at(0) != ctx["fee_payer"]:                     fails.append("account[0] == fee_payer")
    if at(1) != ctx["transfer_destination"]:          fails.append("account[1] == transfer_destination")
    if at(2) != ctx["payTo"]:                         fails.append("account[2] == payTo")
    if at(3) != ctx["payment_mint"]:                  fails.append("account[3] == payment_mint")
    if at(4) != SYSTEM_PROGRAM:                       fails.append("account[4] == System Program")
    if at(5) != ctx["transfer_token_program"]:        fails.append("account[5] == transfer_token_program")
    return fails

def main(path=None):
    path = path or (_HERE / "svm_create_ata_v0.json")
    with open(path, "rb") as fh:
        d = json.loads(fh.read().decode("utf-8"))
    ctx = d["context"]
    ok = True
    for fx in d["fixtures"]:
        instr = fx["instruction"]
        fails = evaluate(instr, ctx)
        verdict = "ACCEPT" if not fails else "REJECT"
        vok = verdict == fx["expected_verdict"]
        aok = set(fails) == set(fx.get("failed_assertions", []))
        # data_b64 must decode to data_hex when both are present
        bok = True
        if "data_b64" in instr:
            bok = base64.b64decode(instr["data_b64"]).hex() == instr.get("data_hex", "")
        good = vok and aok and bok
        ok = ok and good
        print(f"  {'PASS' if good else 'FAIL'}  {fx['id']}: {verdict}"
              + ("" if good else f"  (expected {fx['expected_verdict']}, fails={fails})"))
    print("OK" if ok else "MISMATCH")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
