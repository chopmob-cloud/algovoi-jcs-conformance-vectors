"""Generic preimage runner (Python / algovoi-substrate). Usage: python runner_python.py <set.json>"""
import base64, hashlib, json, sys
from pathlib import Path
from algovoi_substrate.canonicalize import canonicalize
def main(f):
    data = json.loads(Path(f).read_text(encoding="utf-8"))
    p=q=0
    for v in data["vectors"]:
        pay=v.get("preimage")
        if not pay: continue
        c=canonicalize(pay); cb=c.encode() if isinstance(c,str) else c
        b64=base64.b64encode(cb).decode(); dg=hashlib.sha256(cb).hexdigest()
        eh=v.get("expected_transition_hash") or v.get("expected_action_ref")
        if b64==v["expected_jcs_bytes_b64"] and dg==eh: p+=1
        else: q+=1; print(f"  FAIL {v['vector_id']}")
    print(f"{p}/{p+q} PASS"); return 1 if q else 0
if __name__=="__main__": sys.exit(main(sys.argv[1]))
