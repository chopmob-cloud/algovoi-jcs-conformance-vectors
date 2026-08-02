#!/usr/bin/env bash
# settlement_round validity gauntlet -- 8-implementation fail-closed.
# Independent reimplementations of require_positive_int (Substrate Rule 2): a
# settlement_round must be a strictly positive integer; 0, negative, boolean and
# any non-int (incl. numeric strings) are rejected, in all 8 languages.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
VEC="$(cd "$HERE/../../vectors/settlement_attestation_v1" && pwd)/settlement_attestation_v1.json"
LANGS=(python node go php ruby java rust dotnet kotlin elixir)
SEP=";"; case "$(uname -s 2>/dev/null)" in Linux|Darwin) SEP=":" ;; esac
run_lang() {
  case "$1" in
    python) "$(command -v python3 || command -v python)" "$HERE/sr_python.py" "$VEC" ;;
    node)   node "$HERE/sr_node.mjs" "$VEC" ;;
    go)     ( cd "$HERE" && GO111MODULE=on go run sr_go.go "$VEC" ) ;;
    php)    php "$HERE/sr_php.php" "$VEC" ;;
    ruby)   ruby "$HERE/sr_ruby.rb" "$VEC" ;;
    java)   ( cd "$HERE/java"
              [ -d libs ] || cp -r "$HERE/../../vectors/retention_chain_v1/runner_java/libs" libs
              [ -f SrRunner.class ] && [ SrRunner.class -nt SrRunner.java ] || javac -cp "libs/*" SrRunner.java
              java -cp ".${SEP}libs/*" SrRunner "$VEC" ) ;;
    rust)   ( cd "$HERE/rust" && cargo +stable-x86_64-pc-windows-gnu run --bin sr --release --quiet -- "$VEC" 2>/dev/null \
              || cargo run --bin sr --release --quiet -- "$VEC" ) ;;
    dotnet) ( cd "$HERE/dotnet_sr" && dotnet run -c Release --verbosity quiet -- "$VEC" ) ;;
    kotlin) ( cd "$HERE"; KOTLINC="$(command -v kotlinc || echo /opt/kotlinc/bin/kotlinc)"; CP="$(echo java/libs/*.jar | tr ' ' "$SEP")"
              [ -f kotlin/ktsr.jar ] && [ kotlin/ktsr.jar -nt kotlin/KtSr.kt ] || "$KOTLINC" kotlin/KtSr.kt -cp "$CP" -include-runtime -d kotlin/ktsr.jar >/dev/null 2>&1
              java -cp "kotlin/ktsr.jar${SEP}java/libs/*" KtSr "$VEC" ) ;;
    elixir) elixir "$HERE/el_sr.exs" "$VEC" ;;
  esac
}
echo "=== settlement_round validity gauntlet (require_positive_int, 8-impl) ==="
tok=0; tot=0; green=1
for lang in "${LANGS[@]}"; do
  line=$(run_lang "$lang" 2>/dev/null | grep -E "^SETTLEMENT-ROUND-GAUNTLET " | tail -1)
  if [ -z "$line" ]; then printf "  %-8s ERROR\n" "$lang"; green=0; continue; fi
  frac="${line##* }"; printf "  %-8s %s\n" "$lang" "$frac"
  ok="${frac%%/*}"; n="${frac##*/}"; tok=$((tok+ok)); tot=$((tot+n)); [ "$ok" = "$n" ] || green=0
done
echo "TOTAL: ${tok}/${tot}"; [ "$green" = 1 ] && { echo "RESULT: ALL GREEN"; exit 0; } || { echo "RESULT: NOT GREEN"; exit 1; }
