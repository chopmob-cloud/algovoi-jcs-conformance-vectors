# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 AlgoVoi (chopmob-cloud). Conformance layer, Apache-2.0.
import json, hashlib, pathlib
from algovoi_substrate import canonicalize

def artifact_ref(task_ref, output_hash, artifact_type, produced_at_ms):
    payload = {"artifact_type": artifact_type, "output_hash": output_hash, "produced_at_ms": produced_at_ms, "task_ref": task_ref}
    return "sha256:" + hashlib.sha256(canonicalize(payload).encode("utf-8")).hexdigest()

d = json.loads(pathlib.Path(__file__).with_name("artifact_ref_v1.json").read_text(encoding="utf-8"))
refs, p, t = {}, 0, 0
for v in d["vectors"]:
    t += 1; r = artifact_ref(v["task_ref"], v["output_hash"], v["artifact_type"], v["produced_at_ms"]); refs[v["id"]] = r
    ok = r == v["expected_artifact_ref"]; p += ok
    print(("  PASS " if ok else "  FAIL ") + v["id"])
for v in d.get("type_coverage_vectors", []):
    t += 1; r = artifact_ref(v["task_ref"], v["output_hash"], v["artifact_type"], v["produced_at_ms"]); refs[v["id"]] = r
    ok = r == v["expected_artifact_ref"] and r != refs[v["diverges_from"]]; p += ok
    print(("  PASS " if ok else "  FAIL ") + v["id"] + " (type=" + v["artifact_type"] + ", diverges from " + v["diverges_from"] + ")")
for v in d.get("invariant_vectors", []):
    t += 1; ok = artifact_ref(v["task_ref"], v["output_hash"], v["artifact_type"], v["produced_at_ms"]) == refs[v["equals_ref_of"]]; p += ok
    print(("  PASS " if ok else "  FAIL ") + v["id"] + " (equals " + v["equals_ref_of"] + ")")
for v in d.get("negative_vectors", []):
    t += 1; ok = artifact_ref(v["task_ref"], v["output_hash"], v["artifact_type"], v["produced_at_ms"]) != refs[v["diverges_from"]]; p += ok
    print(("  PASS " if ok else "  FAIL ") + v["id"] + " (diverges from " + v["diverges_from"] + ")")
print("PY artifact_ref_v1: %d/%d" % (p, t)); raise SystemExit(0 if p == t else 1)
