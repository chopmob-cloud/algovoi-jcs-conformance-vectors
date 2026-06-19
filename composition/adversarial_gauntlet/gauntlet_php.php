<?php
// Adversarial gauntlet runner -- PHP (independent reimplementation, no algovoi import).
// Same three checks; must accept the control and reject all 11 mutations.
// Usage: php gauntlet_php.php /path/to/adversarial_isolation_v1.json

function hex64($s) { return is_string($s) && preg_match('/^[0-9a-f]{64}$/', $s) === 1; }
function uintv($x) { return is_int($x) && $x >= 0; } // is_int(true) is false in PHP
function nestr($x) { return is_string($x) && $x !== ''; }

function jcs_flat($o) {
    // sorted-key compact JSON; byte-identical to RFC 8785 JCS for ASCII/int payloads.
    ksort($o);
    $parts = [];
    foreach ($o as $k => $v) {
        $parts[] = json_encode((string)$k) . ':' . json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
    return '{' . implode(',', $parts) . '}';
}

function check_transition_preimage($o) {
    if (!is_array($o)) return false;
    if (!hex64($o['action_ref'] ?? null)) return false;
    if (!nestr($o['state'] ?? null)) return false;
    foreach (['transition_timestamp_ms', 'authority_verified_at_ms', 'revocation_check_at_ms'] as $k) {
        if (!uintv($o[$k] ?? null)) return false;
    }
    return true;
}

function check_action_ref($o) {
    if (!is_array($o)) return false;
    foreach (['agent_id', 'action_type', 'scope'] as $k) {
        if (!nestr($o[$k] ?? null)) return false;
    }
    return uintv($o['timestamp_ms'] ?? null);
}

function check_audit_chain($rows) {
    if (!is_array($rows) || count($rows) === 0) return false;
    $prev = null;
    foreach ($rows as $i => $r) {
        if (!is_array($r)) return false;
        if (($r['chain_position'] ?? null) !== $i) return false;
        if ($i === 0) {
            if (($r['prev_hash'] ?? 'x') !== null) return false;
        } else {
            if (($r['prev_hash'] ?? null) !== $prev) return false;
        }
        $recomputed = hash('sha256', jcs_flat($r['payload']));
        if ($recomputed !== ($r['content_hash'] ?? null)) return false;
        $prev = $r['content_hash'];
    }
    return true;
}

$checks = [
    'transition_preimage' => 'check_transition_preimage',
    'action_ref' => 'check_action_ref',
    'audit_chain' => 'check_audit_chain',
];

$data = json_decode(file_get_contents($argv[1]), true);
$ok = 0; $total = 0;
foreach ($data['vectors'] as $v) {
    $total++;
    $verdict = $checks[$v['check']]($v['input']) ? 'accept' : 'reject';
    $expected = ($v['expectation'] === 'reject') ? 'reject' : 'accept';
    $good = $verdict === $expected;
    if ($good) $ok++;
    echo "{$v['vector_id']} {$verdict} expect={$expected} " . ($good ? 'OK' : 'MISMATCH') . "\n";
}
echo "GAUNTLET php {$ok}/{$total}\n";
exit($ok === $total ? 0 : 1);
