"""ZKP receipt v1 conformance vector runner (Python / rfc8785)."""
import json, hashlib, base64, sys
try:
    import rfc8785
except ImportError:
    sys.stderr.write(
        "missing dependency 'rfc8785': install it before running "
        "(pip install rfc8785). This runner does not self-install, so a "
        "verifier is never allowed to mutate its environment or reach the "
        "network mid-run.\n")
    sys.exit(2)

data = json.load(open("zkp_receipt_v1.json"))
pass_, fail = 0, 0
for v in data["vectors"]:
    payload = v["receipt"]
    canon = rfc8785.dumps(payload)
    b64 = base64.b64encode(canon).decode()
    digest = hashlib.sha256(canon).hexdigest()
    if b64 == v["expected_jcs_bytes_b64"] and digest == v["expected_content_hash"]:
        pass_ += 1
    else:
        fail += 1
        print(f"  FAIL {v['vector_id']}")
        print(f"    got digest:  {digest}")
        print(f"    want digest: {v['expected_content_hash']}")
print(f"{pass_}/{pass_ + fail} PASS")
sys.exit(1 if fail else 0)
