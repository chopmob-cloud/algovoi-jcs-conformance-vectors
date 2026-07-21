<?php
// Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE at the repo root.
/**
 * Generic preimage runner (PHP 8.1+ / inline JCS RFC 8785, patched edition).
 *
 * Validates sha256(JCS(vector.preimage)) and the canonical bytes for every vector
 * in a set file. Usage: php runner_php.php <set.json>
 *
 * This carries the PATCHED inline canonicaliser from vectors/jcs_edge_v1/runner_php.php,
 * not the older generic one used by the pre-2026-07-19 attestations. The older copy threw
 * on floats and escaped U+2028, and the jws_anchor_v1 JCS-side fixture re-caught both
 * immediately, because its canon-sensitive vector carries U+2028 and the 1.0 integral
 * float form:
 *
 *   PATCH 1 (UTF-8 generation, RFC 8785 section 3.2.4): string and key encoding must add
 *   JSON_UNESCAPED_LINE_TERMINATORS. JSON_UNESCAPED_UNICODE alone still escapes U+2028 /
 *   U+2029 to the backslash-u form, diverging from the literal UTF-8 bytes every
 *   conformant JCS library emits. Same class as the Go encoding/json bug (a2a-go#368).
 *
 *   PATCH 2 (number form, RFC 8785 section 3.2.2.3): a float whose value is integral
 *   canonicalises to the integer form (1.0 becomes 1).
 */

function jcs_canonicalize($value): string {
    if ($value === null) return "null";
    if (is_bool($value)) return $value ? "true" : "false";
    if (is_int($value)) return (string)$value;
    if (is_float($value)) {
        // PATCH 2: ES6 number form, integral floats take the integer form.
        if (is_finite($value) && floor($value) === $value && abs($value) < 9.2e18) {
            return (string)(int)$value;
        }
        throw new Exception("non-integral float ES6 formatting not implemented for this set");
    }
    if (is_string($value)) {
        // PATCH 1: keep U+2028 / U+2029 literal.
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
        // RFC 8785 section 3.2.3: sort by UTF-16 code-unit order, correct for
        // supplementary-plane keys too.
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

$path = $argv[1] ?? null;
if ($path === null) { fwrite(STDERR, "usage: php runner_php.php <set.json>\n"); exit(2); }
$data = json_decode(file_get_contents($path), false, 512, JSON_THROW_ON_ERROR);
$pass = 0; $fail = 0;
foreach ($data->vectors as $v) {
    $payload = $v->preimage ?? $v->receipt ?? null;
    if ($payload === null) continue;
    $canon = jcs_canonicalize($payload);
    $b64 = base64_encode($canon);
    $digest = hash('sha256', $canon);
    $expHash = $v->expected_content_sha256 ?? $v->expected_sha256 ?? $v->expected_content_hash ?? null;
    if ($b64 === $v->expected_jcs_bytes_b64 && $digest === $expHash) {
        $pass++;
    } else {
        $fail++;
        echo "  FAIL {$v->vector_id}\n";
    }
}
echo ($pass) . "/" . ($pass + $fail) . " PASS\n";
exit($fail ? 1 : 0);
