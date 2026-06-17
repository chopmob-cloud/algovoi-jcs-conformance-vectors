<?php
// Generic preimage runner (PHP / inline JCS RFC 8785). Usage: php runner_php.php <set.json>
function jcs_canonicalize($v): string {
    if ($v === null) return "null";
    if (is_bool($v)) return $v ? "true" : "false";
    if (is_int($v)) return (string)$v;
    if (is_float($v)) throw new Exception("floats unsupported");
    if (is_string($v)) return json_encode($v, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    if (is_array($v)) {
        if (array_is_list($v)) return "[" . implode(",", array_map('jcs_canonicalize', $v)) . "]";
        $keys = array_keys($v); sort($keys, SORT_STRING); $parts = [];
        foreach ($keys as $k) { $parts[] = json_encode((string)$k, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR) . ":" . jcs_canonicalize($v[$k]); }
        return "{" . implode(",", $parts) . "}";
    }
    throw new Exception("unsupported type");
}
$data = json_decode(file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR);
$p = 0; $q = 0;
foreach ($data["vectors"] as $v) {
    if (empty($v["preimage"])) continue;
    $canon = jcs_canonicalize($v["preimage"]);
    $b64 = base64_encode($canon); $dg = hash("sha256", $canon);
    $eh = $v["expected_content_sha256"] ?? $v["expected_transition_hash"] ?? $v["expected_action_ref"];
    if ($b64 === $v["expected_jcs_bytes_b64"] && $dg === $eh) $p++;
    else { $q++; echo "  FAIL " . $v["vector_id"] . "\n"; }
}
echo "$p/" . ($p + $q) . " PASS\n";
exit($q === 0 ? 0 : 1);
