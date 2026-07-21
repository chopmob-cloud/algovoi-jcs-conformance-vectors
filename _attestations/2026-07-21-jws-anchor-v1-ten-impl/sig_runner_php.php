<?php
// Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE at the repo root.
//
// jws_anchor_v1 signature + anchor runner (PHP 8 / libsodium, bundled since PHP 7.2).
// Asserts, for every signed vector: the compact JWS verifies under the RFC 8032
// section 7.1 key, and the anchor is sha256 of the RAW SIGNED BYTES.
// Usage: php sig_runner_php.php <jws_anchor_v1.json>

function b64url_decode(string $s): string {
    $pad = strlen($s) % 4;
    if ($pad) { $s .= str_repeat('=', 4 - $pad); }
    return base64_decode(strtr($s, '-_', '+/'));
}
function strip_prefix(string $h): string {
    $i = strpos($h, ':');
    return $i === false ? $h : substr($h, $i + 1);
}

$path = $argv[1] ?? null;
if ($path === null) { fwrite(STDERR, "usage: php sig_runner_php.php <set.json>\n"); exit(2); }
$d = json_decode(file_get_contents($path), false, 512, JSON_THROW_ON_ERROR);
$pub = hex2bin($d->signing_key->public_key_hex);

$pass = 0; $fail = 0;
$check = function (string $id, string $what, bool $ok) use (&$pass, &$fail) {
    if ($ok) { $pass++; } else { $fail++; echo "  FAIL $id ($what)\n"; }
};

foreach ($d->vectors as $v) {
    if (($v->anchor_rule ?? '') !== 'signed_bytes') continue;
    $token = $v->input ?? $v->issuer_jwt ?? $v->presentation ?? null;
    if ($token === null) continue;          // recanon-negative carries no token
    $jwt = explode('~', $token, 2)[0];

    $parts = explode('.', $jwt);
    if (count($parts) !== 3) { $check($v->vector_id, 'not a compact JWS', false); continue; }
    $sig = b64url_decode($parts[2]);
    $signing_input = $parts[0] . '.' . $parts[1];
    $check($v->vector_id, 'ed25519 verify',
        sodium_crypto_sign_verify_detached($sig, $signing_input, $pub));

    $want = $v->expected_anchor ?? $v->presentation_hash ?? null;
    if ($want !== null) {
        $check($v->vector_id, 'anchor = sha256(raw signed bytes)',
            hash('sha256', $token) === strip_prefix($want));
    }
}
echo "$pass/" . ($pass + $fail) . " PASS\n";
exit($fail ? 1 : 0);
