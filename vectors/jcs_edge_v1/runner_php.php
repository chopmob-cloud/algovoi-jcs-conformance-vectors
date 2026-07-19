<?php
// Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE at the repo root.
/**
 * jcs_edge_v1 runner (PHP 8.1+ / inline JCS RFC 8785, patched for the edge cases).
 *
 * This is the conformant version of the corpus's inline PHP JCS. jcs_edge_v1
 * surfaced two gaps in the original ~50-line inline implementation that never
 * showed up on the earlier receipt formats (which contained neither line
 * separators nor floats):
 *
 *   PATCH 1 (UTF-8 generation, RFC 8785 section 3.2.4): string encoding must add
 *   JSON_UNESCAPED_LINE_TERMINATORS. JSON_UNESCAPED_UNICODE alone still escapes
 *   U+2028 / U+2029 to their backslash-u form, which diverges from the literal
 *   UTF-8 bytes every conformant JCS library emits. This is the PHP instance of
 *   the same class as the Go encoding/json U+2028 bug (a2a-go#368).
 *
 *   PATCH 2 (number form, RFC 8785 section 3.2.2.3): a float whose value is an
 *   integer (e.g. 1.0) canonicalises to the integer form (1), not "1.0".
 *
 * Usage: php runner_php.php [vector_set_json]
 */

function jcs_canonicalize($value): string {
    if ($value === null) return "null";
    if (is_bool($value)) return $value ? "true" : "false";
    if (is_int($value)) return (string)$value;
    if (is_float($value)) {
        // PATCH 2: RFC 8785 section 3.2.2.3 (ES6 number form). Integral floats
        // canonicalise to the integer form. (jcs_edge_v1 exercises only 1.0.)
        if (is_finite($value) && floor($value) === $value
            && abs($value) < 9.2e18) {
            return (string)(int)$value;
        }
        throw new Exception("non-integral float ES6 formatting not implemented for this set");
    }
    if (is_string($value)) {
        // PATCH 1: add JSON_UNESCAPED_LINE_TERMINATORS so U+2028 / U+2029 stay literal.
        return json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
            | JSON_UNESCAPED_LINE_TERMINATORS | JSON_THROW_ON_ERROR);
    }
    if (is_array($value)) {
        $items = array_map('jcs_canonicalize', $value);
        return "[" . implode(",", $items) . "]";
    }
    if (is_object($value)) {
        $arr = get_object_vars($value);
        $keys = array_keys($arr);
        // RFC 8785 section 3.2.3: sort by UTF-16 code-unit order (UTF-16BE bytes),
        // correct for supplementary-plane keys too.
        usort($keys, fn($a, $b) => strcmp(
            iconv('UTF-8', 'UTF-16BE', (string)$a),
            iconv('UTF-8', 'UTF-16BE', (string)$b)));
        $parts = [];
        foreach ($keys as $k) {
            $k_canon = json_encode((string)$k, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
                | JSON_UNESCAPED_LINE_TERMINATORS | JSON_THROW_ON_ERROR);
            $parts[] = "$k_canon:" . jcs_canonicalize($arr[$k]);
        }
        return "{" . implode(",", $parts) . "}";
    }
    throw new Exception("unsupported type: " . gettype($value));
}

$path = $argv[1] ?? (__DIR__ . "/jcs_edge_v1.json");
$data = json_decode(file_get_contents($path), false, 512, JSON_THROW_ON_ERROR);
$pass = 0; $fail = 0;
foreach ($data->vectors as $v) {
    $payload = $v->preimage ?? $v->receipt;
    $canon = jcs_canonicalize($payload);
    $bytes = $canon; // already UTF-8
    $b64 = base64_encode($bytes);
    $digest = hash('sha256', $bytes);
    $expHash = $v->expected_sha256 ?? $v->expected_content_hash;
    if ($b64 === $v->expected_jcs_bytes_b64 && $digest === $expHash) {
        $pass++;
    } else {
        $fail++;
        echo "  FAIL {$v->vector_id}\n";
    }
}
echo ($pass) . "/" . ($pass + $fail) . " PASS\n";
exit($fail ? 1 : 0);
