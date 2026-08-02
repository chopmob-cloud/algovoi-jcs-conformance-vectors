<?php
// Differential adversarial substrate -- PHP canon probe (inline RFC 8785 JCS).
// Contract: see probe_python.py. Emits "<id>\t h:<hex> | R:<reason>" per case.

function jcs_canonicalize($value): string {
    if ($value === null) return "null";
    if (is_bool($value)) return $value ? "true" : "false";
    if (is_int($value)) return (string)$value;
    if (is_float($value)) throw new Exception("floats not supported");
    if (is_string($value)) return json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    if (is_array($value)) return "[" . implode(",", array_map('jcs_canonicalize', $value)) . "]";
    if (is_object($value)) {
        $arr = get_object_vars($value);
        $keys = array_keys($arr);
        usort($keys, fn($a, $b) => strcmp(iconv('UTF-8', 'UTF-16BE', (string)$a), iconv('UTF-8', 'UTF-16BE', (string)$b)));
        $parts = [];
        foreach ($keys as $k) {
            $k_c = json_encode((string)$k, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            $parts[] = "$k_c:" . jcs_canonicalize($arr[$k]);
        }
        return "{" . implode(",", $parts) . "}";
    }
    throw new Exception("unsupported type");
}

$d = json_decode(file_get_contents($argv[1]));
$out = [];
foreach ($d->cases as $c) {
    $val = json_decode($c->raw);                 // native parser
    if (json_last_error() !== JSON_ERROR_NONE) { $out[] = "$c->id\tR:parse"; continue; }
    try { $v = "h:" . hash("sha256", jcs_canonicalize($val)); }
    catch (\Throwable $e) { $v = "R:canon"; }
    $out[] = "$c->id\t$v";
}
echo implode("\n", $out) . "\n";
