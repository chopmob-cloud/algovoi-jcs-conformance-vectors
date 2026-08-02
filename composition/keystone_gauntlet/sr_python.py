#!/usr/bin/env python3
"""settlement_round validity gauntlet -- Python impl (require_positive_int)."""
import json, sys
def rpi(v):
    if isinstance(v, bool) or not isinstance(v, int): raise ValueError("not int")
    if v <= 0: raise ValueError("not positive")
    return v
def main(path):
    d = json.load(open(path, encoding="utf-8")); ok = 0; fails = []
    for r in d["settlement_round_reject_vectors"]:
        try: rpi(r["receipt"].get("settlement_round")); fails.append(f"{r['vector_id']}: bad round ACCEPTED")
        except Exception: ok += 1
    acc = [v for v in d["vectors"] if isinstance(v.get("receipt", {}).get("settlement_round"), int) and not isinstance(v["receipt"]["settlement_round"], bool)]
    try: rpi(acc[0]["receipt"]["settlement_round"]); ok += 1
    except Exception: fails.append(f"{acc[0]['vector_id']}: valid round REJECTED")
    total = len(d["settlement_round_reject_vectors"]) + 1
    for f in fails: print("  FAIL", f)
    print(f"SETTLEMENT-ROUND-GAUNTLET python {ok}/{total}")
    return 0 if ok == total and not fails else 1
if __name__ == "__main__": sys.exit(main(sys.argv[1]))
