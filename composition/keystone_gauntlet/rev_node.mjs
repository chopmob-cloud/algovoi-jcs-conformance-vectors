// revocation_ref fail-closed gauntlet -- Node impl (canonicalize).
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import canonicalize from "canonicalize";
const REF=/^sha256:[0-9a-f]{64}$/;
const REASONS=new Set(["USER_REQUESTED","COMPLIANCE_TRIGGERED","EXPIRED","KEY_COMPROMISE","SUPERSEDED","ADMIN"]);
const STATUS=new Set(["active","suspended","revoked","inactive"]);
const rr=v=>{if(typeof v!=="string"||!REF.test(v))throw 0;return v;};
const ri=v=>{if(typeof v==="boolean"||!Number.isInteger(v)||v<0)throw 0;return v;};
const re_=(v,s)=>{if(!s.has(v))throw 0;return v;};
const rs=v=>{if(typeof v!=="string"||v==="")throw 0;return v;};
function h(o){return "sha256:"+createHash("sha256").update(Buffer.from(canonicalize(o),"utf-8")).digest("hex");}
function rref(f){const p=f.prev_revocation_ref;return h({canon_version:"jcs-rfc8785-v1",type:"revocation_link",
  subject_ref:rr(f.subject_ref),revoked_at_ms:ri(f.revoked_at_ms),reason_code:re_(f.reason_code,REASONS),
  issuer_did:rs(f.issuer_did),prev_status:re_(f.prev_status,STATUS),new_status:re_(f.new_status,STATUS),
  seq:ri(f.seq),prev_revocation_ref:(p===null||p===undefined)?null:rr(p)});}
function vchain(links){let prev=null;for(let i=0;i<links.length;i++){const l=links[i];
  if(l.seq!==i||(l.prev_revocation_ref??null)!==prev)return false;prev=h(l);}return true;}
const d=JSON.parse(readFileSync(process.argv[2],"utf-8"));let ok=0;const fails=[];
for(const v of d.vectors){try{rref(v)===v.expected_revocation_ref?ok++:fails.push(v.id);}catch{fails.push(v.id);}}
for(const n of d.negatives){try{rref(n);fails.push(n.id);}catch{ok++;}}
for(const t of d.tamper){rref(t)!==t.claimed_revocation_ref?ok++:fails.push(t.id);}
for(const c of d.chain_valid){vchain(c.links)?ok++:fails.push(c.id);}
for(const c of d.chain_invalid){!vchain(c.links)?ok++:fails.push(c.id);}
const total=d.vectors.length+d.negatives.length+d.tamper.length+d.chain_valid.length+d.chain_invalid.length;
for(const f of fails)console.log("  FAIL",f);
console.log(`REVOCATION-GAUNTLET node ${ok}/${total}`);
process.exit(ok===total&&fails.length===0?0:1);
