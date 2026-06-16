"""Retention Chain v0 vector runner -- Python / rfc8785@0.1.4

Usage: python runner_python.py <vector_set_json>

Validates sha256(JCS(preimage)) == expected_chain_ref for each vector.
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

from rfc8785 import dumps as jcs_dumps


def main(vector_file: str) -> int:
    data = json.loads(Path(vector_file).read_text(encoding="utf-8"))
    pass_n = fail_n = 0
    for v in data["vectors"]:
        vid = v["vector_id"]
        canon = jcs_dumps(v["preimage"])
        b64   = base64.b64encode(canon).decode()
        ref   = "sha256:" + hashlib.sha256(canon).hexdigest()
        b64_ok = b64 == v["expected_jcs_bytes_b64"]
        ref_ok = ref == v["expected_chain_ref"]
        if b64_ok and ref_ok:
            pass_n += 1
        else:
            fail_n += 1
            if not b64_ok: print(f"  FAIL {vid} jcs_bytes_b64 mismatch")
            if not ref_ok: print(f"  FAIL {vid} chain_ref (got {ref})")
    print(f"{pass_n}/{pass_n + fail_n} PASS")
    return 1 if fail_n else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
