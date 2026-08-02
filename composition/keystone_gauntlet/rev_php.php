<?php
// revocation_ref fail-closed gauntlet -- PHP impl (inline RFC 8785 JCS).
function jcs_canonicalize($value):string{
  if($value===null)return "null"; if(is_bool($value))return $value?"true":"false"; if(is_int($value))return (string)$value;
  if(is_float($value))throw new Exception("float"); if(is_string($value))return json_encode($value,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
  if(is_array($value))return "[".implode(",",array_map('jcs_canonicalize',$value))."]";
  if(is_object($value)){ $arr=get_object_vars($value); $keys=array_keys($arr);
    usort($keys,fn($a,$b)=>strcmp(iconv('UTF-8','UTF-16BE',(string)$a),iconv('UTF-8','UTF-16BE',(string)$b)));
    $p=[]; foreach($keys as $k){ $p[]=json_encode((string)$k,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR).":".jcs_canonicalize($arr[$k]); }
    return "{".implode(",",$p)."}"; }
  throw new Exception("type");
}
function ref_ok($s){return is_string($s)&&preg_match('/^sha256:[0-9a-f]{64}$/',$s)===1;}
function h($o){return "sha256:".hash("sha256",jcs_canonicalize($o));}
$REASONS=["USER_REQUESTED","COMPLIANCE_TRIGGERED","EXPIRED","KEY_COMPROMISE","SUPERSEDED","ADMIN"];
$STATUS=["active","suspended","revoked","inactive"];
function rref($f,$REASONS,$STATUS){
  if(!ref_ok($f->subject_ref))throw new Exception();
  if(is_bool($f->revoked_at_ms)||!is_int($f->revoked_at_ms)||$f->revoked_at_ms<0)throw new Exception();
  if(!in_array($f->reason_code,$REASONS,true))throw new Exception();
  if(!is_string($f->issuer_did)||$f->issuer_did==="")throw new Exception();
  if(!in_array($f->prev_status,$STATUS,true))throw new Exception();
  if(!in_array($f->new_status,$STATUS,true))throw new Exception();
  if(is_bool($f->seq)||!is_int($f->seq)||$f->seq<0)throw new Exception();
  $prev=property_exists($f,'prev_revocation_ref')?$f->prev_revocation_ref:null;
  if($prev!==null&&!ref_ok($prev))throw new Exception();
  $o=new stdClass(); $o->canon_version="jcs-rfc8785-v1"; $o->type="revocation_link"; $o->subject_ref=$f->subject_ref;
  $o->revoked_at_ms=$f->revoked_at_ms; $o->reason_code=$f->reason_code; $o->issuer_did=$f->issuer_did;
  $o->prev_status=$f->prev_status; $o->new_status=$f->new_status; $o->seq=$f->seq; $o->prev_revocation_ref=$prev;
  return h($o);
}
function vchain($links){ $prev=null; foreach($links as $i=>$l){ if($l->seq!==$i)return false; $lp=property_exists($l,'prev_revocation_ref')?$l->prev_revocation_ref:null; if($lp!==$prev)return false; $prev=h($l); } return true; }
$d=json_decode(file_get_contents($argv[1])); $ok=0; $fails=[];
foreach($d->vectors as $v){ try{ rref($v,$REASONS,$STATUS)===$v->expected_revocation_ref?$ok++:$fails[]=$v->id; }catch(Exception $e){ $fails[]=$v->id; } }
foreach($d->negatives as $n){ try{ rref($n,$REASONS,$STATUS); $fails[]=$n->id; }catch(Exception $e){ $ok++; } }
foreach($d->tamper as $t){ rref($t,$REASONS,$STATUS)!==$t->claimed_revocation_ref?$ok++:$fails[]=$t->id; }
foreach($d->chain_valid as $c){ vchain($c->links)?$ok++:$fails[]=$c->id; }
foreach($d->chain_invalid as $c){ !vchain($c->links)?$ok++:$fails[]=$c->id; }
$total=count($d->vectors)+count($d->negatives)+count($d->tamper)+count($d->chain_valid)+count($d->chain_invalid);
foreach($fails as $f) echo "  FAIL $f\n";
echo "REVOCATION-GAUNTLET php $ok/$total\n";
exit($ok===$total&&count($fails)===0?0:1);
