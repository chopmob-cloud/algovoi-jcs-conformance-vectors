"""Generic input runner (Python / algovoi-substrate). Claim 1 (input bytes) only.
Usage: python runner_python.py <set.json>"""
import base64, hashlib, json, sys
from pathlib import Path
from algovoi_substrate.canonicalize import canonicalize

def main(f):
    data = json.loads(Path(f).read_text(encoding="utf-8")); p = q = 0
    for v in data["vectors"]:
        obj = v.get("input")
        if obj is None:
            continue
        c = canonicalize(obj); cb = c.encode() if isinstance(c, str) else c
        if base64.b64encode(cb).decode() == v["input_jcs_bytes_b64"] and hashlib.sha256(cb).hexdigest() == v["input_content_sha256"]:
            p += 1
        else:
            q += 1; print(f"  FAIL {v['vector_id']}")
    print(f"{p}/{p+q} PASS"); return 1 if q else 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
