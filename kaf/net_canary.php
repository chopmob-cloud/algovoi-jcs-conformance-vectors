<?php
// KAF network canary (real program file, never run via php -r/eval).
// Exit 0 iff the network is UNREACHABLE (hermetic). Exit 1 otherwise.
$reachable = [];
foreach ([["1.1.1.1", 443], ["8.8.8.8", 53]] as $hp) {
    $errno = 0; $errstr = "";
    $fp = @fsockopen($hp[0], $hp[1], $errno, $errstr, 2.0);
    if ($fp !== false) { fclose($fp); $reachable[] = "tcp {$hp[0]}:{$hp[1]}"; }
    // A timeout (fsockopen sets errno 0) is INCONCLUSIVE, not proof of isolation:
    // fail closed. A real errno (ECONNREFUSED/ENETUNREACH/EHOSTUNREACH) IS isolation.
    elseif ($errno === 0) { $reachable[] = "tcp {$hp[0]}:{$hp[1]} (timeout: inconclusive, fail-closed)"; }
}
$ip = @gethostbyname("one.one.one.one");
if ($ip !== "one.one.one.one" && filter_var($ip, FILTER_VALIDATE_IP)) {
    $reachable[] = "dns one.one.one.one";
}
if (count($reachable) > 0) {
    echo "NETWORK=REACHABLE " . implode("; ", $reachable) . "\n";
    exit(1);
}
echo "NETWORK=NONE (all probes failed, hermetic)\n";
exit(0);
