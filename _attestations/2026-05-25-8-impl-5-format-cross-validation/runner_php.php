<?php
/**
 * Generic vector-set runner (PHP 8.1+ / inline JCS RFC 8785).
 *
 * Pure stdlib implementation of JCS canonicalization (no composer dep).
 * Implements the rules from RFC 8785 sufficient for the receipt-format
 * vectors in this corpus (no floats; no Unicode escapes beyond what
 * JSON_UNESCAPED_UNICODE handles).
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
    if (is_array($value)) {
        // Distinguish list vs assoc: PHP array semantics
        $is_list = array_is_list($value);
        if ($is_list) {
            $items = array_map('jcs_canonicalize', $value);
            return "[" . implode(",", $items) . "]";
        }
        // Object: sort keys lexicographically per RFC 8785 UTF-16 code-point order
        // For ASCII keys (which is the case for our vectors) this equals byte order
        $keys = array_keys($value);
        sort($keys, SORT_STRING);
        $parts = [];
        foreach ($keys as $k) {
            $k_canon = json_encode($k, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            $v_canon = jcs_canonicalize($value[$k]);
            $parts[] = "$k_canon:$v_canon";
        }
        return "{" . implode(",", $parts) . "}";
    }
    throw new Exception("unsupported type: " . gettype($value));
}

$vector_file = $argv[1];
$data = json_decode(file_get_contents($vector_file), true, 512, JSON_THROW_ON_ERROR);

$pass = 0;
$fail = 0;
foreach ($data["vectors"] as $v) {
    $payload = $v["receipt"] ?? $v["response"] ?? $v["row"] ?? null;
    if ($payload === null) continue;
    $canon = jcs_canonicalize($payload);
    $b64 = base64_encode($canon);
    $digest = hash("sha256", $canon);
    $expected_hash = $v["expected_content_hash"] ?? $v["expected_row_content_hash"];
    if ($b64 === $v["expected_jcs_bytes_b64"] && $digest === $expected_hash) {
        $pass++;
    } else {
        $fail++;
        echo "  FAIL " . $v["vector_id"] . "\n";
    }
}
echo "$pass/" . ($pass + $fail) . " PASS\n";
exit($fail === 0 ? 0 : 1);
