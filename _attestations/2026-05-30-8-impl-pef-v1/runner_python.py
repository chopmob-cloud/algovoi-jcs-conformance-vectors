"""PEF v1 vector runner -- Python / rfc8785@0.1.4

Usage: python runner_python.py <vector_set_json>

Validates that sha256(JCS(preimage)) == expected_frame_id for each vector.
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

        # --- 1. receipt hash ---
        receipt_bytes = jcs_dumps(v["receipt"])
        receipt_b64   = base64.b64encode(receipt_bytes).decode()
        receipt_hash  = "sha256:" + hashlib.sha256(receipt_bytes).hexdigest()
        receipt_ok = (receipt_b64  == v["expected_receipt_jcs_bytes_b64"] and
                      receipt_hash == v["expected_receipt_hash"])

        # --- 2. preimage hash (= frame_id) ---
        preimage_bytes = jcs_dumps(v["preimage"])
        preimage_b64   = base64.b64encode(preimage_bytes).decode()
        frame_id       = "sha256:" + hashlib.sha256(preimage_bytes).hexdigest()
        preimage_ok = (preimage_b64 == v["expected_preimage_jcs_bytes_b64"] and
                       frame_id     == v["expected_frame_id"])

        if receipt_ok and preimage_ok:
            pass_n += 1
        else:
            fail_n += 1
            if not receipt_ok:
                print(f"  FAIL {vid} receipt_hash mismatch")
            if not preimage_ok:
                print(f"  FAIL {vid} frame_id mismatch (got {frame_id})")

    print(f"{pass_n}/{pass_n + fail_n} PASS")
    return 1 if fail_n else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
