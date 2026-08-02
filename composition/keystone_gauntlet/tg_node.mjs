// trust_gate deny-table gauntlet -- Node impl.
import { readFileSync } from "node:fs";
const DENY = { block_untrusted: new Set(["UNTRUSTED"]), require_trusted: new Set(["UNTRUSTED", "PROVISIONAL", "INSUFFICIENT_EVIDENCE"]) };
function blocks(mode, verdict) { if (!mode || mode === "off") return false; return (DENY[mode] ?? new Set()).has(verdict); }
const d = JSON.parse(readFileSync(process.argv[2], "utf-8")); let ok = 0; const fails = [];
for (const v of d.vectors) { blocks(v.mode, v.verdict) === v.expected_blocks ? ok++ : fails.push(`${v.id}: mismatch`); }
for (const f of fails) console.log("  FAIL", f);
console.log(`TRUST-GATE-GAUNTLET node ${ok}/${d.vectors.length}`);
process.exit(ok === d.vectors.length && fails.length === 0 ? 0 : 1);
