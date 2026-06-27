# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 AlgoVoi (chopmob-cloud). Conformance layer, Apache-2.0.
import json, hashlib, pathlib
from algovoi_substrate import canonicalize

def card_ref(card):
    prepared = {k: v for k, v in card.items() if k != "signatures"}
    return "sha256:" + hashlib.sha256(canonicalize(prepared).encode("utf-8")).hexdigest()

d = json.loads(pathlib.Path(__file__).with_name("card_ref_v1.json").read_text(encoding="utf-8"))
refs, p, t = {}, 0, 0
for v in d["vectors"]:
    t += 1; r = card_ref(v["card"]); refs[v["id"]] = r
    ok = r == v["expected_card_ref"]; p += ok
    print(("  PASS " if ok else "  FAIL ") + v["id"])
for v in d["invariant_vectors"]:
    t += 1; ok = card_ref(v["card"]) == refs[v["equals_ref_of"]]; p += ok
    print(("  PASS " if ok else "  FAIL ") + v["id"] + " (equals " + v["equals_ref_of"] + ")")
for v in d["negative_vectors"]:
    t += 1; ok = card_ref(v["card"]) != refs[v["diverges_from"]]; p += ok
    print(("  PASS " if ok else "  FAIL ") + v["id"] + " (diverges from " + v["diverges_from"] + ")")
print("PY card_ref_v1: %d/%d" % (p, t)); raise SystemExit(0 if p == t else 1)
