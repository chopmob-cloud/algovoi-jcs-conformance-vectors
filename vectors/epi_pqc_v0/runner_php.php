<?php
/**
 * epi_pqc_v0 runner -- PHP 8.1+ / inline JCS RFC 8785
 *
 * JCS canonicalisation check only: sha256(JCS(input)) == frame_id
 * Falcon-1024 signature + key-lineage checks: Python runner only.
 *
 * Usage (from epi_pqc_v0/):  php runner_php.php
 */

function jcs_canonicalize($value): string {
    if ($value === null) return "null";
    if (is_bool($value)) return $value ? "true" : "false";
    if (is_int($value)) return (string)$value;
    if (is_float($value)) {
        if (is_nan($value) || is_infinite($value)) throw new Exception("non-finite float");
        return json_encode($value, JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR);
    }
    if (is_string($value)) {
        return json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }
    if (is_array($value)) {
        if (array_is_list($value)) {
            return "[" . implode(",", array_map('jcs_canonicalize', $value)) . "]";
        }
        $keys = array_keys($value);
        usort($keys, fn($a, $b) => strcmp(iconv('UTF-8', 'UTF-16BE', (string)$a), iconv('UTF-8', 'UTF-16BE', (string)$b)));
        $parts = [];
        foreach ($keys as $k) {
            $kc = json_encode((string)$k, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            $parts[] = "$kc:" . jcs_canonicalize($value[$k]);
        }
        return "{" . implode(",", $parts) . "}";
    }
    if (is_object($value)) {
        $arr  = get_object_vars($value);
        $keys = array_keys($arr);
        usort($keys, fn($a, $b) => strcmp(iconv('UTF-8', 'UTF-16BE', (string)$a), iconv('UTF-8', 'UTF-16BE', (string)$b)));
        $parts = [];
        foreach ($keys as $k) {
            $kc = json_encode((string)$k, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            $parts[] = "$kc:" . jcs_canonicalize($arr[$k]);
        }
        return "{" . implode(",", $parts) . "}";
    }
    throw new Exception("unsupported type: " . gettype($value));
}

$here = __DIR__;
$data = json_decode(file_get_contents("$here/epi_pqc_v0.json"), false, 512, JSON_THROW_ON_ERROR);
$pass = 0; $fail = 0;

foreach ($data->vectors as $v) {
    $canon  = jcs_canonicalize($v->input);
    $b64    = base64_encode($canon);
    $ref    = "sha256:" . hash("sha256", $canon);
    $b64_ok = $b64 === $v->expected_jcs_bytes_b64;
    $ref_ok = $ref === $v->frame_id;
    if ($b64_ok && $ref_ok) {
        $pass++;
    } else {
        $fail++;
        if (!$b64_ok) echo "  FAIL " . $v->id . " jcs_bytes_b64 mismatch\n";
        if (!$ref_ok) echo "  FAIL " . $v->id . " frame_id (got $ref)\n";
    }
}
echo "$pass/" . ($pass + $fail) . " PASS (JCS only)\n";
exit($fail === 0 ? 0 : 1);
