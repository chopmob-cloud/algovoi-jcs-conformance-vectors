<?php
// runner_php.php -- RFC 9421 §2.5-CONFORMANT cross-validation runner for the
// rfc9421_proxy_chain_v1 fixture. Independent reimplementation (no AlgoVoi
// package): rebuilds the conformant signing base from scratch and verifies
// with libsodium (built into PHP 7.2+).
//
// Run: php runner_php.php   (from the dir containing request.fixture.json)

$fix = json_decode(file_get_contents("request.fixture.json"), true);

$method    = $fix["request"]["method"];               // PRESERVE case
$path      = $fix["request"]["path"];
$authority = strtolower($fix["request"]["authority"]);
$cd        = $fix["request"]["headers"]["content-digest"];
$si        = $fix["request"]["headers"]["signature-input"];
$sigHeader = $fix["request"]["headers"]["signature"];
$expected  = $fix["signing"]["signing_base"];
$pubHex    = $fix["keypair"]["public_key_hex"];

// Post-label portion of Signature-Input: after the first '='.
$paramsRaw = substr($si, strpos($si, "=") + 1);
// Covered components = inner list quoted names.
$inner = substr($paramsRaw, 1, strpos($paramsRaw, ")") - 1);
preg_match_all('/"([^"]+)"/', $inner, $m);
$covered = $m[1];

$lines = [];
foreach ($covered as $name) {
    switch ($name) {
        case "@method":        $val = $method; break;
        case "@authority":     $val = $authority; break;
        case "@path":          $val = $path; break;
        case "content-digest": $val = $cd; break;
        default: fwrite(STDERR, "unexpected covered component: $name\n"); exit(1);
    }
    $lines[] = "\"$name\": $val";
}
$lines[] = "\"@signature-params\": $paramsRaw";
$base = implode("\n", $lines);

if ($base !== $expected) {
    echo "[FAIL] signing base mismatch\n";
    echo "  expected: " . var_export($expected, true) . "\n";
    echo "  got:      " . var_export($base, true) . "\n";
    exit(1);
}
echo "[OK] signing base byte-identical to fixture (rfc9421 conformant)\n";

$expectedCd = "sha-256=:" . base64_encode(hash("sha256", "", true)) . ":";
if ($expectedCd !== $cd) { echo "[FAIL] content-digest mismatch\n"; exit(1); }
echo "[OK] RFC 9530 content-digest verified\n";

$body = rtrim(substr($sigHeader, strpos($sigHeader, "=:") + 2), ":");
$sig = base64_decode($body);
$pub = hex2bin($pubHex);
if (!sodium_crypto_sign_verify_detached($sig, $base, $pub)) {
    echo "[FAIL] Ed25519 verify failed\n";
    exit(1);
}
echo "[OK] Ed25519 signature verified\n";
echo "PASS (PHP: inline conformant base + libsodium)\n";
