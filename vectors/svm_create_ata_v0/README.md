# svm_create_ata_v0

Standalone Solana conformance vectors for the optional idempotent create-associated-token-account (create-ATA) at instruction index 2 in the x402 exact SVM scheme, published for the x402 standards discussion (issue #2395, PR #2798).

These are byte-pin assertions, not a JCS canonicalisation vector: each fixture is a full create-ATA instruction (program id, instruction data, account list) plus the accept/reject verdict and the exact pins it exercises. Data, not a reference implementation: run your own facilitator static-path check against them.

1 positive plus 3 negatives, deterministic keypairs, reproduce byte-for-byte:

- `pos-01` accepts a correct idempotent create: program == ATA program, `data == 0x01`, six-account layout, `account[0]` == fee payer, `account[1]` == the ATA derived from (payTo, token program, mint), `account[2]` == payTo, `account[3]` == mint, `account[4]` == System Program, `account[5]` == token program.
- `neg-01-legacy-create` rejects the legacy non-idempotent `Create` (empty data, 7 accounts).
- `neg-02-tampered-destination` rejects a destination that is not the derived ATA (exercises the recomputation path, not a field match).
- `neg-03-sender-funder` rejects a create funded by the sender rather than the fee payer (the funder pin that closes the rent-sponsorship griefing vector).

`account[1]` in `pos-01` is a real derived address: `findProgramAddress([payTo, token program, mint], ATA program)` reproduces it.

Run the dependency-free verifier (recomputes each verdict from the pins):

    python verify.py

Standalone Solana byte-pin set, not part of the L1 JCS anchor total. Apache-2.0, Copyright 2026 Christopher Hopley / AlgoVoi (chopmob-cloud).
