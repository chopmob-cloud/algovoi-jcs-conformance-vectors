<?php
/**
 * PEF v1 vector runner -- PHP 8.1+ / inline JCS RFC 8785
 *
 * Validates sha256(JCS(receipt)) == expected_receipt_hash and
 *           sha256(JCS(preimage)) == expected_frame_id
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
        $is_list = array_is_list($value);
        if ($is_list) {
            $items = array_map('jcs_canonicalize', $value);
            return "[" . implode(",", $items) . "]";
        }
        $keys = array_keys($value);
        sort($keys, SORT_STRING);
        $parts = [];
        foreach ($keys as $k) {
            $k_c = json_encode($k, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            $v_c = jcs_canonicalize($value[$k]);
            $parts[] = "$k_c:$v_c";
        }
        return "{" . implode(",", $parts) . "}";
    }
    throw new Exception("unsupported type: " . gettype($value));
}

function sha256_jcs($obj): array {
    $canon = jcs_canonicalize($obj);
    return [base64_encode($canon), "sha256:" . hash("sha256", $canon)];
}

$data = json_decode(file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR);
$pass = 0;
$fail = 0;

foreach ($data["vectors"] as $v) {
    [$r_b64, $r_hash] = sha256_jcs($v["receipt"]);
    [$p_b64, $p_hash] = sha256_jcs($v["preimage"]);

    $receipt_ok  = $r_b64 === $v["expected_receipt_jcs_bytes_b64"] &&
                   $r_hash === $v["expected_receipt_hash"];
    $preimage_ok = $p_b64 === $v["expected_preimage_jcs_bytes_b64"] &&
                   $p_hash === $v["expected_frame_id"];

    if ($receipt_ok && $preimage_ok) {
        $pass++;
    } else {
        $fail++;
        if (!$receipt_ok)  echo "  FAIL " . $v["vector_id"] . " receipt_hash\n";
        if (!$preimage_ok) echo "  FAIL " . $v["vector_id"] . " frame_id (got $p_hash)\n";
    }
}
echo "$pass/" . ($pass + $fail) . " PASS\n";
exit($fail === 0 ? 0 : 1);
