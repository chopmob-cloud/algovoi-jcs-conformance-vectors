<?php
/**
 * Generic vector-set runner (PHP 8.1+ / inline JCS RFC 8785).
 *
 * Pure stdlib implementation of JCS canonicalization (no composer dep).
 * Decodes with assoc=false so JSON objects become stdClass and JSON arrays stay arrays — this keeps
 * empty objects ({}) distinct from empty arrays ([]), which assoc=true collapses into the same value.
 *
 * Usage: php runner_php.php <vector_set_json>
 */

function jcs_canonicalize($value): string {
    if ($value === null) return "null";
    if (is_bool($value)) return $value ? "true" : "false";
    if (is_int($value)) return (string)$value;
    if (is_float($value)) {
        // RFC 8785 Section 3.2.2.3 -- not used in this corpus
        throw new Exception("floats not supported in canonical form for these vectors");
    }
    if (is_string($value)) {
        return json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }
    if (is_array($value)) {                 // JSON array (list)
        $items = array_map('jcs_canonicalize', $value);
        return "[" . implode(",", $items) . "]";
    }
    if (is_object($value)) {                // JSON object (stdClass), including empty {}
        $arr = get_object_vars($value);
        $keys = array_keys($arr);
        // RFC 8785: sort by UTF-16 code-unit order (UTF-16BE bytes), correct for astral-plane keys too
        usort($keys, fn($a, $b) => strcmp(iconv('UTF-8', 'UTF-16BE', (string)$a), iconv('UTF-8', 'UTF-16BE', (string)$b)));
        $parts = [];
        foreach ($keys as $k) {
            $k_canon = json_encode((string)$k, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            $parts[] = "$k_canon:" . jcs_canonicalize($arr[$k]);
        }
        return "{" . implode(",", $parts) . "}";
    }
    throw new Exception("unsupported type: " . gettype($value));
}

$vector_file = $argv[1];
$data = json_decode(file_get_contents($vector_file), false, 512, JSON_THROW_ON_ERROR);

$pass = 0;
$fail = 0;
foreach ($data->vectors as $v) {
    $payload = $v->receipt ?? $v->response ?? $v->row ?? null;
    if ($payload === null) continue;
    $canon = jcs_canonicalize($payload);
    $b64 = base64_encode($canon);
    $digest = hash("sha256", $canon);
    $expected_hash = $v->expected_content_hash ?? $v->expected_row_content_hash;
    if ($b64 === $v->expected_jcs_bytes_b64 && $digest === $expected_hash) {
        $pass++;
    } else {
        $fail++;
        echo "  FAIL " . $v->vector_id . "\n";
    }
}
echo "$pass/" . ($pass + $fail) . " PASS\n";
exit($fail === 0 ? 0 : 1);
