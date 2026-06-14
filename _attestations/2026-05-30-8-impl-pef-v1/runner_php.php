<?php
/**
 * PEF v1 vector runner -- PHP 8.1+ / inline JCS RFC 8785
 *
 * Validates sha256(JCS(receipt)) == expected_receipt_hash and
 *           sha256(JCS(preimage)) == expected_frame_id
 *
 * Decodes with assoc=false so JSON objects become stdClass and JSON arrays stay arrays — empty
 * objects ({}) stay distinct from empty arrays ([]), which assoc=true collapses into the same value.
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
    [$r_b64, $r_hash] = sha256_jcs($v->receipt);
    [$p_b64, $p_hash] = sha256_jcs($v->preimage);

    $receipt_ok  = $r_b64 === $v->expected_receipt_jcs_bytes_b64 &&
                   $r_hash === $v->expected_receipt_hash;
    $preimage_ok = $p_b64 === $v->expected_preimage_jcs_bytes_b64 &&
                   $p_hash === $v->expected_frame_id;

    if ($receipt_ok && $preimage_ok) {
        $pass++;
    } else {
        $fail++;
        if (!$receipt_ok)  echo "  FAIL " . $v->vector_id . " receipt_hash\n";
        if (!$preimage_ok) echo "  FAIL " . $v->vector_id . " frame_id (got $p_hash)\n";
    }
}
echo "$pass/" . ($pass + $fail) . " PASS\n";
exit($fail === 0 ? 0 : 1);
