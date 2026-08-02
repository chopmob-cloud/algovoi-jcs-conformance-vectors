#!/usr/bin/env bash
# Keystone L3 guard_context fail-closed gauntlet -- 8-implementation cross-validation.
# Independent reimplementations of guard_context_ref (different JCS library each),
# all accept the positive, fail-close on every negative (timestamp/policy/mandate/
# passport tamper, malformed ref) and hold both invariants (moment-distinctness;
# non-integer guard_timestamp_ms rejected).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
VEC="$(cd "$HERE/../../vectors/keystone_guard_context_v1" && pwd)/keystone_guard_context_v1.json"
LANGS=(python node go php ruby java rust dotnet)
SEP=";"; case "$(uname -s 2>/dev/null)" in Linux|Darwin) SEP=":" ;; esac

run_lang() {
  case "$1" in
    python) "$(command -v python3 || command -v python)" "$HERE/gc_python.py" "$VEC" ;;
    node)   node "$HERE/gc_node.mjs" "$VEC" ;;
    go)     ( cd "$HERE" && GO111MODULE=on go run gc_go.go "$VEC" ) ;;
    php)    php "$HERE/gc_php.php" "$VEC" ;;
    ruby)   ruby "$HERE/gc_ruby.rb" "$VEC" ;;
    java)   ( cd "$HERE/java"
              [ -d libs ] || cp -r "$HERE/../../vectors/retention_chain_v1/runner_java/libs" libs
              [ -f GcRunner.class ] && [ GcRunner.class -nt GcRunner.java ] || javac -cp "libs/*" GcRunner.java
              java -cp ".${SEP}libs/*" GcRunner "$VEC" ) ;;
    rust)   ( cd "$HERE/rust" && cargo +stable-x86_64-pc-windows-gnu run --bin gc --release --quiet -- "$VEC" 2>/dev/null \
              || cargo run --bin gc --release --quiet -- "$VEC" ) ;;
    dotnet) ( cd "$HERE/dotnet_gc" && dotnet run -c Release --verbosity quiet -- "$VEC" ) ;;
  esac
}

echo "================================================================"
echo "KEYSTONE L3 GUARD_CONTEXT GAUNTLET -- fail-closed cross-validation"
echo "vector set: keystone_guard_context_v1 (1 positive + 4 negative + 2 invariant)"
echo "================================================================"
total_ok=0; total=0; green=1
for lang in "${LANGS[@]}"; do
  line=$(run_lang "$lang" 2>/dev/null | grep -E "^KEYSTONE-GAUNTLET-GC " | tail -1)
  if [ -z "$line" ]; then printf "  %-8s ERROR (toolchain?)\n" "$lang"; green=0; continue; fi
  frac="${line##* }"; printf "  %-8s %s\n" "$lang" "$frac"
  ok="${frac%%/*}"; n="${frac##*/}"; total_ok=$((total_ok+ok)); total=$((total+n))
  [ "$ok" = "$n" ] || green=0
done
echo "----------------------------------------------------------------"
echo "TOTAL fail-closed verdicts: ${total_ok}/${total}"
[ "$green" = 1 ] && { echo "RESULT: ALL GREEN"; exit 0; } || { echo "RESULT: NOT GREEN"; exit 1; }
