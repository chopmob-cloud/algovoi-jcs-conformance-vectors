<?php
/**
 * Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE in this directory.
 *
 * Retention Chain v1 vector runner -- PHP 8.1+ / inline JCS RFC 8785
 *
 * Validates sha256(JCS(preimage)) == expected_chain_ref
 *
 * Usage: php runner_php.php <vector_set_json>
 */

function jcs_canonicalize($value): string {
    if ($value === null) return "null";
    if (is_bool($value)) return $value ? "true" : "false";
    if (is_int($value)) return (string)$value;
    if (is_float($value)) {
        throw new Exception("floats not supported for these vectors");
    }
    if (is_string($value)) {
        return json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }
    if (is_array($value)) {
        $items = array_map('jcs_canonicalize', $value);
        return "[" . implode(",", $items) . "]";
    }
    if (is_object($value)) {
        $arr  = get_object_vars($value);
        $keys = array_keys($arr);
        usort($keys, fn($a, $b) => strcmp(iconv('UTF-8', 'UTF-16BE', (string)$a), iconv('UTF-8', 'UTF-16BE', (string)$b)));
        $parts = [];
        foreach ($keys as $k) {
            $k_c = json_encode((string)$k, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            $parts[] = "$k_c:" . jcs_canonicalize($arr[$k]);
        }
        return "{" . implode(",", $parts) . "}";
    }
    throw new Exception("unsupported type: " . gettype($value));
}

function sha256_jcs($obj): array {
    $canon = jcs_canonicalize($obj);
    return [base64_encode($canon), "sha256:" . hash("sha256", $canon)];
}

$data = json_decode(file_get_contents($argv[1]), false, 512, JSON_THROW_ON_ERROR);
$pass = 0;
$fail = 0;

foreach ($data->vectors as $v) {
    [$b64, $ref] = sha256_jcs($v->preimage);
    $b64_ok = $b64 === $v->expected_jcs_bytes_b64;
    $ref_ok = $ref === $v->expected_chain_ref;
    if ($b64_ok && $ref_ok) {
        $pass++;
    } else {
        $fail++;
        if (!$b64_ok) echo "  FAIL " . $v->vector_id . " jcs_bytes_b64 mismatch\n";
        if (!$ref_ok)  echo "  FAIL " . $v->vector_id . " chain_ref (got $ref)\n";
    }
}
echo "$pass/" . ($pass + $fail) . " PASS\n";
exit($fail === 0 ? 0 : 1);
