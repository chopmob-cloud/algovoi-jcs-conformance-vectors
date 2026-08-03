#!/usr/bin/env python3
"""trust_gate deny-table gauntlet -- Python impl."""
import json, sys
DENY = {"block_untrusted": {"UNTRUSTED"}, "require_trusted": {"UNTRUSTED", "PROVISIONAL", "INSUFFICIENT_EVIDENCE"}}
def blocks(mode, verdict):
    if not mode or mode == "off": return False
    return verdict in DENY.get(mode, set())
d = json.load(open(sys.argv[1], encoding="utf-8")); ok = 0; fails = []
for v in d["vectors"]:
    if blocks(v["mode"], v["verdict"]) == v["expected_blocks"]: ok += 1
    else: fails.append(f"{v['id']}: mismatch")
for f in fails: print("  FAIL", f)
print(f"TRUST-GATE-GAUNTLET python {ok}/{len(d['vectors'])}")
sys.exit(0 if len(d["vectors"]) > 0 and ok == len(d["vectors"]) and not fails else 1)  # positive-work floor: never green on zero vectors
