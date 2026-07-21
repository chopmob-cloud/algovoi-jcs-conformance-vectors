<?php
// Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0.
// caip_edge_v1 PHP runner. Correct = \A..\z (PCRE absolute anchors). Naive = ^..$: PCRE's $
// (without the D modifier) matches before a trailing newline, so ^..$ SHARES the anchor trap,
// like Python. Delimiter '~' avoids the '/' in the CAIP-19 pattern.
$CHAIN = '[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}';
function body($k) {
    global $CHAIN;
    if ($k === 'caip2')  return $CHAIN;
    if ($k === 'caip10') return $CHAIN . ':[-.%a-zA-Z0-9]{1,128}';
    return $CHAIN . '/[-a-z0-9]{3,8}:[-.%a-zA-Z0-9]{1,128}(/[-.%a-zA-Z0-9]{1,78})?';
}
$n = 0; $pass = 0; $trap = 0;
foreach (file('corpus.tsv', FILE_IGNORE_NEW_LINES) as $ln) {
    $p = explode("\t", $ln, 3);
    if (count($p) < 3) continue;
    list($exp, $kind, $h) = $p;
    $s = hex2bin($h);
    $want = $exp === 'accept';
    $ok = preg_match('~\A' . body($kind) . '\z~', $s) === 1;
    if ($ok === $want) $pass++;
    $n++;
    if ($exp === 'reject' && preg_match('~^' . body($kind) . '$~', $s) === 1) $trap++;
}
printf("PHP(PCRE) correct %d/%d | naive ^..$ over-accepts %d reject-vectors\n", $pass, $n, $trap);
exit($pass === $n ? 0 : 1);
