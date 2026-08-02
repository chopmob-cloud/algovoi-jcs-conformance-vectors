<?php
// Keystone L3 gauntlet -- guard_context, PHP impl (inline RFC 8785 JCS).
// Usage: php gc_php.php <keystone_guard_context_v1.json>

function jcs_canonicalize($value): string {
    if ($value === null) return "null";
    if (is_bool($value)) return $value ? "true" : "false";
    if (is_int($value)) return (string)$value;
    if (is_float($value)) throw new Exception("floats not supported");
    if (is_string($value)) return json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    if (is_array($value)) return "[" . implode(",", array_map('jcs_canonicalize', $value)) . "]";
    if (is_object($value)) {
        $arr = get_object_vars($value); $keys = array_keys($arr);
        usort($keys, fn($a, $b) => strcmp(iconv('UTF-8', 'UTF-16BE', (string)$a), iconv('UTF-8', 'UTF-16BE', (string)$b)));
        $parts = [];
        foreach ($keys as $k) {
            $k_c = json_encode((string)$k, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            $parts[] = "$k_c:" . jcs_canonicalize($arr[$k]);
        }
        return "{" . implode(",", $parts) . "}";
    }
    throw new Exception("unsupported type");
}
function ref_ok($s): bool { return is_string($s) && preg_match('/^sha256:[0-9a-f]{64}$/', $s) === 1; }

function guard_context_ref($ts, $policy_ref, $mandate_ref, $passport_credential_ref): string {
    if (!is_int($ts) || $ts < 0) throw new Exception("guard_timestamp_ms must be non-negative int");
    foreach (["policy_ref" => $policy_ref, "mandate_ref" => $mandate_ref, "passport_credential_ref" => $passport_credential_ref] as $n => $val) {
        if (!ref_ok($val)) throw new Exception("$n must be sha256: ref");
    }
    $o = new stdClass();
    $o->canon_version = "jcs-rfc8785-v1"; $o->type = "guard_context";
    $o->guard_timestamp_ms = $ts; $o->policy_ref = $policy_ref; $o->mandate_ref = $mandate_ref; $o->passport_credential_ref = $passport_credential_ref;
    return "sha256:" . hash("sha256", jcs_canonicalize($o));
}

$d = json_decode(file_get_contents($argv[1]));
$ok = 0; $fails = [];
foreach ($d->vectors as $v) {
    try { $got = guard_context_ref($v->guard_timestamp_ms, $v->policy_ref, $v->mandate_ref, $v->passport_credential_ref);
        if ($got === $v->expected_guard_context_ref) $ok++; else $fails[] = "$v->id: accept-mismatch";
    } catch (Exception $e) { $fails[] = "$v->id: " . $e->getMessage(); }
}
foreach ($d->negatives as $n) {
    if ($n->must === "reject") {
        try { guard_context_ref($n->guard_timestamp_ms, $n->policy_ref, $n->mandate_ref, $n->passport_credential_ref); $fails[] = "$n->id: invalid ACCEPTED"; }
        catch (Exception $e) { $ok++; }
    } else {
        $got = guard_context_ref($n->guard_timestamp_ms, $n->policy_ref, $n->mandate_ref, $n->passport_credential_ref);
        if ($got !== $n->claimed_guard_context_ref) $ok++; else $fails[] = "$n->id: tamper NOT detected";
    }
}
$v0 = $d->vectors[0];
$a = guard_context_ref($v0->guard_timestamp_ms, $v0->policy_ref, $v0->mandate_ref, $v0->passport_credential_ref);
$b = guard_context_ref($v0->guard_timestamp_ms + 1, $v0->policy_ref, $v0->mandate_ref, $v0->passport_credential_ref);
if ($a !== $b) $ok++; else $fails[] = "moment-distinctness collision";
try { guard_context_ref(1720000000000.5, $v0->policy_ref, $v0->mandate_ref, $v0->passport_credential_ref); $fails[] = "float-ts accepted"; }
catch (Exception $e) { $ok++; }

$total = count($d->vectors) + count($d->negatives) + 2;
foreach ($fails as $f) echo "  FAIL $f\n";
echo "KEYSTONE-GAUNTLET-GC php $ok/$total\n";
exit($ok === $total && count($fails) === 0 ? 0 : 1);
