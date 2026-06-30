# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 AlgoVoi (chopmob-cloud). Conformance layer, Apache-2.0.
import json, hashlib, pathlib
from algovoi_substrate import canonicalize

def task_ref(card_ref, instructions_hash, created_at_ms):
    payload = {"card_ref": card_ref, "created_at_ms": created_at_ms, "instructions_hash": instructions_hash}
    return "sha256:" + hashlib.sha256(canonicalize(payload).encode("utf-8")).hexdigest()

d = json.loads(pathlib.Path(__file__).with_name("task_ref_v1.json").read_text(encoding="utf-8"))
refs, p, t = {}, 0, 0
for v in d["vectors"]:
    t += 1; r = task_ref(v["card_ref"], v["instructions_hash"], v["created_at_ms"]); refs[v["id"]] = r
    ok = r == v["expected_task_ref"]; p += ok
    print(("  PASS " if ok else "  FAIL ") + v["id"])
for v in d["invariant_vectors"]:
    t += 1; ok = task_ref(v["card_ref"], v["instructions_hash"], v["created_at_ms"]) == refs[v["equals_ref_of"]]; p += ok
    print(("  PASS " if ok else "  FAIL ") + v["id"] + " (equals " + v["equals_ref_of"] + ")")
for v in d.get("negative_vectors", []):
    t += 1; ok = task_ref(v["card_ref"], v["instructions_hash"], v["created_at_ms"]) != refs[v["diverges_from"]]; p += ok
    print(("  PASS " if ok else "  FAIL ") + v["id"] + " (diverges from " + v["diverges_from"] + ")")
print("PY task_ref_v1: %d/%d" % (p, t)); raise SystemExit(0 if p == t else 1)
