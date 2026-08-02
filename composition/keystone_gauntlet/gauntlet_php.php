<?php
// Keystone L3 fail-closed gauntlet -- PHP impl (inline RFC 8785 JCS).
// Independent reimplementation of decision_audit_ref (no algovoi import).
// Usage: php gauntlet_php.php <keystone_decision_audit_v1.json>

function jcs_canonicalize($value): string {
    if ($value === null) return "null";
    if (is_bool($value)) return $value ? "true" : "false";
    if (is_int($value)) return (string)$value;
    if (is_float($value)) throw new Exception("floats not supported");
    if (is_string($value)) return json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    if (is_array($value)) return "[" . implode(",", array_map('jcs_canonicalize', $value)) . "]";
    if (is_object($value)) {
        $arr = get_object_vars($value);
        $keys = array_keys($arr);
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

function decision_audit_ref($dr, $pcr, $mr, $pbr, $sbr = null): string {
    foreach (["decision_ref" => $dr, "passport_credential_ref" => $pcr, "mandate_ref" => $mr, "policy_bound_ref" => $pbr] as $n => $val) {
        if (!ref_ok($val)) throw new Exception("$n must be sha256: ref");
    }
    $obj = new stdClass();
    $obj->decision_ref = $dr; $obj->passport_credential_ref = $pcr; $obj->mandate_ref = $mr; $obj->policy_bound_ref = $pbr;
    if ($sbr !== null) {
        if (!ref_ok($sbr)) throw new Exception("screen_binding_ref must be sha256: ref");
        $obj->screen_binding_ref = $sbr;
    }
    return "sha256:" . hash("sha256", jcs_canonicalize($obj));
}

$d = json_decode(file_get_contents($argv[1]));
$ok = 0; $fails = [];
foreach ($d->vectors as $v) {
    try {
        $got = decision_audit_ref($v->decision_ref, $v->passport_credential_ref, $v->mandate_ref, $v->policy_bound_ref, $v->screen_binding_ref ?? null);
        if ($got === $v->expected_decision_audit_ref) $ok++; else $fails[] = "$v->id: accept-mismatch";
    } catch (Exception $e) { $fails[] = "$v->id: " . $e->getMessage(); }
}
foreach ($d->negatives as $n) {
    if ($n->must === "reject") {
        try { decision_audit_ref($n->decision_ref, $n->passport_credential_ref, $n->mandate_ref, $n->policy_bound_ref, $n->screen_binding_ref ?? null); $fails[] = "$n->id: invalid ACCEPTED"; }
        catch (Exception $e) { $ok++; }
    } else {
        $got = decision_audit_ref($n->decision_ref, $n->passport_credential_ref, $n->mandate_ref, $n->policy_bound_ref, $n->screen_binding_ref ?? null);
        if ($got !== $n->claimed_decision_audit_ref) $ok++; else $fails[] = "$n->id: tamper NOT detected";
    }
}
$v0 = $d->vectors[0];
$a = decision_audit_ref($v0->decision_ref, $v0->passport_credential_ref, $v0->mandate_ref, $v0->policy_bound_ref, $v0->screen_binding_ref);
$b = decision_audit_ref($v0->decision_ref, $v0->passport_credential_ref, $v0->mandate_ref, $v0->policy_bound_ref, null);
if ($a !== $b) $ok++; else $fails[] = "screen-distinctness collision";
try { decision_audit_ref("bad", $v0->passport_credential_ref, $v0->mandate_ref, $v0->policy_bound_ref); $fails[] = "malformed-ref accepted"; }
catch (Exception $e) { $ok++; }

$total = count($d->vectors) + count($d->negatives) + 2;
foreach ($fails as $f) echo "  FAIL $f\n";
echo "KEYSTONE-GAUNTLET php $ok/$total\n";
exit($ok === $total && count($fails) === 0 ? 0 : 1);
