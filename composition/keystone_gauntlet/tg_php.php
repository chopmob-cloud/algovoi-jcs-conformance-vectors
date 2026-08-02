<?php
// trust_gate deny-table gauntlet -- PHP impl.
$DENY = ["block_untrusted" => ["UNTRUSTED"], "require_trusted" => ["UNTRUSTED", "PROVISIONAL", "INSUFFICIENT_EVIDENCE"]];
function blocks($DENY, $mode, $verdict) { if (!$mode || $mode === "off") return false; return in_array($verdict, $DENY[$mode] ?? [], true); }
$d = json_decode(file_get_contents($argv[1])); $ok = 0; $fails = [];
foreach ($d->vectors as $v) { if (blocks($DENY, $v->mode, $v->verdict) === $v->expected_blocks) $ok++; else $fails[] = "$v->id: mismatch"; }
foreach ($fails as $f) echo "  FAIL $f\n";
echo "TRUST-GATE-GAUNTLET php $ok/" . count($d->vectors) . "\n";
exit($ok === count($d->vectors) && count($fails) === 0 ? 0 : 1);
