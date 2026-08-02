#!/usr/bin/env python3
"""Differential adversarial substrate -- N-way consensus engine.

Reads:
  --out   DIR   directory of per-language verdict files (out/<lang>.txt), each a
                list of "<id>\\t<verdict>" lines produced by a canon probe.
  corpora ...   one or more corpus JSON files: {"pillar":..., "cases":[{id, raw,
                expect, note}]}. expect in {agree, reject, document}.

Consensus rules (the novel property -- impossible with a 2-impl corpus):
  agree    -> every present implementation must emit the SAME h:<hash>.
              A hash split OR any rejection is a consensus FAILURE.
  reject   -> every present implementation must reject (R:*). Reasons may differ.
              Any implementation that produced a hash is a consensus FAILURE.
  document -> known cross-implementation divergence hazard. Never fails the
              suite; the driver prints the partition (which impls land where) as
              a HAZARD MAP so the substrate layer can gate such inputs out of any
              preimage. "10000% by design": we prove where canonicalizers split
              and forbid those shapes, rather than hoping they never occur.

Exit 0 iff every agree/reject case reaches full N-way consensus.
"""
from __future__ import annotations
import glob, json, os, sys


def load_verdicts(out_dir: str) -> dict[str, dict[str, str]]:
    """lang -> {case_id: verdict}"""
    m: dict[str, dict[str, str]] = {}
    for p in sorted(glob.glob(os.path.join(out_dir, "*.txt"))):
        lang = os.path.splitext(os.path.basename(p))[0]
        d: dict[str, str] = {}
        for line in open(p, encoding="utf-8"):
            line = line.rstrip("\n")
            if not line or "\t" not in line:
                continue
            cid, v = line.split("\t", 1)
            d[cid] = v.strip()
        m[lang] = d
    return m


def main(argv: list[str]) -> int:
    out_dir = "out"
    corpora = []
    i = 0
    while i < len(argv):
        if argv[i] == "--out":
            out_dir = argv[i + 1]; i += 2
        else:
            corpora.append(argv[i]); i += 1
    if not corpora:
        print("usage: differential_driver.py --out DIR corpus1.json [corpus2.json ...]")
        return 2

    verdicts = load_verdicts(out_dir)
    langs = sorted(verdicts.keys())
    if not langs:
        print(f"no verdict files in {out_dir}/")
        return 2

    cases = []
    for cp in corpora:
        doc = json.load(open(cp, encoding="utf-8"))
        for c in doc["cases"]:
            c["_pillar"] = doc.get("pillar", os.path.basename(cp))
            cases.append(c)

    print("=" * 68)
    print("DIFFERENTIAL ADVERSARIAL SUBSTRATE -- N-way consensus")
    print(f"implementations present ({len(langs)}): {', '.join(langs)}")
    print(f"cases: {len(cases)}  corpora: {', '.join(os.path.basename(c) for c in corpora)}")
    print("=" * 68)

    n_pass = n_fail = n_hazard = 0
    fails = []
    hazards = []
    agreed_hash: dict[str, str] = {}  # case_id -> the single consensus hash (agree cases only)
    by_id = {c["id"]: c for c in cases}
    for c in cases:
        cid = c["id"]; expect = c["expect"]
        vs = {L: verdicts[L].get(cid, "R:absent") for L in langs}
        distinct = sorted(set(vs.values()))
        hashes = {v for v in vs.values() if v.startswith("h:")}
        rejects = {L for L, v in vs.items() if v.startswith("R:")}

        if expect == "agree":
            if len(hashes) == 1 and not rejects:
                n_pass += 1
                agreed_hash[cid] = next(iter(hashes))
            else:
                n_fail += 1
                fails.append((cid, expect, vs))
        elif expect == "reject":
            if not hashes:
                n_pass += 1
            else:
                n_fail += 1
                fails.append((cid, expect, vs))
        elif expect == "document":
            n_hazard += 1
            # partition langs by verdict for the hazard map
            part: dict[str, list[str]] = {}
            for L, v in vs.items():
                part.setdefault(v, []).append(L)
            # normalized shape: all R:* collapse to REJECT, distinct hashes stay distinct
            shapes = {("REJECT" if v.startswith("R:") else v) for v in vs.values()}
            hazards.append((cid, c.get("note", ""), part, len(shapes)))
        else:
            n_fail += 1
            fails.append((cid, f"BAD-EXPECT:{expect}", vs))

    # ---- relational invariants across cases (verified across all N impls) ----
    rel_pass = rel_fail = 0
    rel_fails = []
    for c in cases:
        cid = c["id"]
        if "same_as" in c:
            other = c["same_as"]
            a, b = agreed_hash.get(cid), agreed_hash.get(other)
            if a is not None and b is not None and a == b:
                rel_pass += 1
            else:
                rel_fail += 1
                rel_fails.append(f"same_as  {cid} == {other}  ({a} vs {b})")
        if "differs_from" in c:
            other = c["differs_from"]
            a, b = agreed_hash.get(cid), agreed_hash.get(other)
            if a is not None and b is not None and a != b:
                rel_pass += 1
            else:
                rel_fail += 1
                rel_fails.append(f"differs_from  {cid} != {other}  ({a} vs {b})")

    # ---- report ----
    if fails:
        print("\nCONSENSUS FAILURES (must be zero):")
        for cid, expect, vs in fails:
            print(f"  [{expect}] {cid}")
            part: dict[str, list[str]] = {}
            for L, v in vs.items():
                part.setdefault(v, []).append(L)
            for v, ls in sorted(part.items()):
                print(f"      {v:<72} <- {', '.join(ls)}")

    if hazards:
        print("\nHAZARD MAP (documented cross-impl divergence; gated out of preimages):")
        for cid, note, part, n_shapes in hazards:
            split = "SPLIT" if n_shapes > 1 else "uniform-reject" if all(v.startswith("R:") for v in part) else "uniform"
            print(f"  {cid}  [{split}] {note}")
            for v, ls in sorted(part.items()):
                print(f"      {v:<72} <- {', '.join(ls)}")

    if rel_fails:
        print("\nRELATIONAL INVARIANT FAILURES (must be zero):")
        for f in rel_fails:
            print(f"  {f}")

    print("\n" + "-" * 68)
    print(f"agree/reject consensus:  PASS {n_pass}  FAIL {n_fail}")
    print(f"relational invariants:   PASS {rel_pass}  FAIL {rel_fail}")
    print(f"hazard cases mapped:     {n_hazard}")
    if n_fail == 0 and rel_fail == 0:
        print(f"RESULT: FULL {len(langs)}-WAY CONSENSUS on every agree/reject case + all relational invariants.")
        return 0
    print("RESULT: CONSENSUS BROKEN -- see failures above.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
