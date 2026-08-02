#!/usr/bin/env python3
"""revocation_ref fail-closed gauntlet -- Python impl (rfc8785)."""
import hashlib, json, re, sys
import rfc8785
REF=re.compile(r"^sha256:[0-9a-f]{64}$")
REASONS=("USER_REQUESTED","COMPLIANCE_TRIGGERED","EXPIRED","KEY_COMPROMISE","SUPERSEDED","ADMIN")
STATUS=("active","suspended","revoked","inactive")
def _ref(v):
    if not isinstance(v,str) or not REF.match(v): raise ValueError()
    return v
def _int(v):
    if isinstance(v,bool) or not isinstance(v,int) or v<0: raise ValueError()
    return v
def _enum(v,a):
    if v not in a: raise ValueError()
    return v
def _str(v):
    if not isinstance(v,str) or v=="": raise ValueError()
    return v
def rref(f):
    prev=f.get("prev_revocation_ref")
    obj={"canon_version":"jcs-rfc8785-v1","type":"revocation_link","subject_ref":_ref(f["subject_ref"]),
         "revoked_at_ms":_int(f["revoked_at_ms"]),"reason_code":_enum(f["reason_code"],REASONS),
         "issuer_did":_str(f["issuer_did"]),"prev_status":_enum(f["prev_status"],STATUS),
         "new_status":_enum(f["new_status"],STATUS),"seq":_int(f["seq"]),
         "prev_revocation_ref":None if prev is None else _ref(prev)}
    return "sha256:"+hashlib.sha256(rfc8785.dumps(obj)).hexdigest()
def vchain(links):
    prev=None
    for i,l in enumerate(links):
        if l.get("seq")!=i or l.get("prev_revocation_ref")!=prev: return False
        prev="sha256:"+hashlib.sha256(rfc8785.dumps(l)).hexdigest()
    return True
d=json.load(open(sys.argv[1],encoding="utf-8")); ok=0; fails=[]
for v in d["vectors"]:
    try: ok+=1 if rref(v)==v["expected_revocation_ref"] else fails.append(v["id"]) or 0
    except Exception: fails.append(v["id"])
for n in d["negatives"]:
    try: rref(n); fails.append(n["id"])
    except Exception: ok+=1
for t in d["tamper"]: ok+=1 if rref(t)!=t["claimed_revocation_ref"] else fails.append(t["id"]) or 0
for c in d["chain_valid"]: ok+=1 if vchain(c["links"]) else fails.append(c["id"]) or 0
for c in d["chain_invalid"]: ok+=1 if not vchain(c["links"]) else fails.append(c["id"]) or 0
total=len(d["vectors"])+len(d["negatives"])+len(d["tamper"])+len(d["chain_valid"])+len(d["chain_invalid"])
for f in fails: print("  FAIL",f)
print(f"REVOCATION-GAUNTLET python {ok}/{total}")
sys.exit(0 if ok==total and not fails else 1)
