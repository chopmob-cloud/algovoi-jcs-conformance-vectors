<?php
/**
 * runner_php.php -- RFC 9421 + RFC 9530 cross-validation runner for the
 * rfc9421_proxy_chain_v0 fixture.
 *
 * Uses PHP libsodium (ext-sodium, ships with PHP 7.2+) for Ed25519 +
 * hash('sha256') stdlib + json_decode + preg_match. No external dependencies.
 *
 * Run from the directory containing request.fixture.json:
 *   php runner_php.php
 */

$json = file_get_contents("request.fixture.json");
$fix = json_decode($json, true);

$method = strtolower($fix["request"]["method"]);
$path = $fix["request"]["path"];
$authority = strtolower($fix["request"]["authority"]);
$cdHeader = $fix["request"]["headers"]["content-digest"];
$siHeader = $fix["request"]["headers"]["signature-input"];
$sigHeader = $fix["request"]["headers"]["signature"];
$expectedBase = $fix["signing"]["signing_base"];
$pubHex = $fix["keypair"]["public_key_hex"];

function parseSignatureInput($value) {
    $eqParen = strpos($value, "=(");
    $body = ($eqParen !== false && $eqParen > 0) ? substr($value, $eqParen + 1) : $value;
    $close = strpos($body, ")");
    $inside = substr($body, 1, $close - 1);
    $params = substr($body, $close + 1);
    if (strlen($params) > 0 && $params[0] === ";") $params = substr($params, 1);

    preg_match_all('/"([^"]+)"/', $inside, $matches);
    $covered = $matches[1];

    $paramMap = [];
    foreach (explode(";", $params) as $kv) {
        $kv = trim($kv);
        if ($kv === "") continue;
        $eq = strpos($kv, "=");
        if ($eq !== false) {
            $k = substr($kv, 0, $eq);
            $v = trim(substr($kv, $eq + 1), '"');
            $paramMap[$k] = $v;
        }
    }
    return [$covered, $paramMap];
}

function parseSignatureValue($value) {
    $eqColon = strpos($value, "=:");
    $body = ($eqColon !== false) ? substr($value, $eqColon + 2) : ltrim($value, ":");
    $body = rtrim($body, ":");
    return base64_decode($body);
}

[$covered, $params] = parseSignatureInput($siHeader);

$lines = [];
foreach ($covered as $name) {
    switch ($name) {
        case "@method": $val = $method; break;
        case "@authority": $val = $authority; break;
        case "@path": $val = $path; break;
        case "content-digest": $val = $cdHeader; break;
        case "created": $val = $params["created"]; break;
        default: throw new Exception("unknown component: $name");
    }
    $lines[] = '"' . $name . '": ' . $val;
}
$signingBase = implode("\n", $lines);

if ($signingBase !== $expectedBase) {
    echo "[FAIL] signing base mismatch\n";
    echo "  expected: " . var_export($expectedBase, true) . "\n";
    echo "  got:      " . var_export($signingBase, true) . "\n";
    exit(1);
}
echo "[OK] signing base byte-identical to fixture\n";

$digest = hash("sha256", "", true);
$expectedCd = "sha-256=:" . base64_encode($digest) . ":";
if ($expectedCd !== $cdHeader) {
    echo "[FAIL] content-digest mismatch\n";
    exit(1);
}
echo "[OK] RFC 9530 content-digest verified\n";

$pubKey = hex2bin($pubHex);
$sigBytes = parseSignatureValue($sigHeader);

if (!sodium_crypto_sign_verify_detached($sigBytes, $signingBase, $pubKey)) {
    echo "[FAIL] Ed25519 verify failed\n";
    exit(1);
}
echo "[OK] Ed25519 signature verified\n";
echo "PASS (PHP libsodium: sodium_crypto_sign_verify_detached + hash sha256)\n";
