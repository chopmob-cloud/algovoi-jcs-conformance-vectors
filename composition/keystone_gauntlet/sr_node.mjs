// settlement_round validity gauntlet -- Node impl.
import { readFileSync } from "node:fs";
function rpi(v){ if(typeof v==="boolean") throw new Error("bool"); if(typeof v!=="number"||!Number.isInteger(v)) throw new Error("not int"); if(v<=0) throw new Error("not positive"); return v; }
const d=JSON.parse(readFileSync(process.argv[2],"utf-8")); let ok=0; const fails=[];
for(const r of d.settlement_round_reject_vectors){ try{ rpi(r.receipt.settlement_round); fails.push(`${r.vector_id}: bad round ACCEPTED`);}catch{ ok++; } }
const acc=d.vectors.find(v=>Number.isInteger(v.receipt?.settlement_round));
try{ rpi(acc.receipt.settlement_round); ok++; }catch{ fails.push(`${acc.vector_id}: valid round REJECTED`); }
const total=d.settlement_round_reject_vectors.length+1;
for(const f of fails) console.log("  FAIL",f);
console.log(`SETTLEMENT-ROUND-GAUNTLET node ${ok}/${total}`);
process.exit(ok===total&&fails.length===0?0:1);
