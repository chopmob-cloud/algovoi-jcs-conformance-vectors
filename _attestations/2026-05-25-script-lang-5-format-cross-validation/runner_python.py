"""Generic vector-set runner (Python / rfc8785@0.1.4 via algovoi-substrate).

Usage: python runner_python.py <vector_set_json>
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

from algovoi_substrate.canonicalize import canonicalize

def main(vector_file: str) -> int:
    data = json.loads(Path(vector_file).read_text(encoding="utf-8"))
    pass_n, fail_n = 0, 0
    for v in data["vectors"]:
        payload = v.get("receipt") or v.get("response") or v.get("row")
        if not payload:
            continue
        canon = canonicalize(payload)
        canon_bytes = canon.encode("utf-8") if isinstance(canon, str) else canon
        b64 = base64.b64encode(canon_bytes).decode("ascii")
        digest = hashlib.sha256(canon_bytes).hexdigest()
        expected_hash = v.get("expected_content_hash") or v.get("expected_row_content_hash")
        if b64 == v["expected_jcs_bytes_b64"] and digest == expected_hash:
            pass_n += 1
        else:
            fail_n += 1
            print(f"  FAIL {v['vector_id']}")
    print(f"{pass_n}/{pass_n+fail_n} PASS")
    return 1 if fail_n else 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
