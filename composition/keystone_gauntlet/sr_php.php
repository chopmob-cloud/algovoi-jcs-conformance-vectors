<?php
// settlement_round validity gauntlet -- PHP impl.
function rpi($v){ if(is_bool($v)) throw new Exception("bool"); if(!is_int($v)) throw new Exception("not int"); if($v<=0) throw new Exception("not positive"); return $v; }
$d=json_decode(file_get_contents($argv[1])); $ok=0; $fails=[];
foreach($d->settlement_round_reject_vectors as $r){ try{ rpi($r->receipt->settlement_round); $fails[]="$r->vector_id: bad round ACCEPTED"; }catch(Exception $e){ $ok++; } }
$acc=null; foreach($d->vectors as $v){ if(isset($v->receipt->settlement_round) && is_int($v->receipt->settlement_round)){ $acc=$v; break; } }
try{ rpi($acc->receipt->settlement_round); $ok++; }catch(Exception $e){ $fails[]="$acc->vector_id: valid round REJECTED"; }
$total=count($d->settlement_round_reject_vectors)+1;
foreach($fails as $f) echo "  FAIL $f\n";
echo "SETTLEMENT-ROUND-GAUNTLET php $ok/$total\n";
exit($ok===$total && count($fails)===0 ? 0 : 1);
