#!/usr/bin/env bash
# trust_gate deny-table gauntlet -- 8-implementation cross-validation.
# Independent reimplementations of _trust_gate_blocks (gateway/app/routers/verify.py)
# all computing the same allow/deny for the full verdict x mode matrix + fail-open edges.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
VEC="$(cd "$HERE/../../vectors/trust_gate_v1" && pwd)/trust_gate_v1.json"
LANGS=(python node go php ruby java rust dotnet)
SEP=";"; case "$(uname -s 2>/dev/null)" in Linux|Darwin) SEP=":" ;; esac
run_lang() {
  case "$1" in
    python) python "$HERE/tg_python.py" "$VEC" ;;
    node)   node "$HERE/tg_node.mjs" "$VEC" ;;
    go)     ( cd "$HERE" && GO111MODULE=on go run tg_go.go "$VEC" ) ;;
    php)    php "$HERE/tg_php.php" "$VEC" ;;
    ruby)   ruby "$HERE/tg_ruby.rb" "$VEC" ;;
    java)   ( cd "$HERE/java"
              [ -d libs ] || cp -r "$HERE/../../vectors/retention_chain_v1/runner_java/libs" libs
              [ -f TgRunner.class ] && [ TgRunner.class -nt TgRunner.java ] || javac -cp "libs/*" TgRunner.java
              java -cp ".${SEP}libs/*" TgRunner "$VEC" ) ;;
    rust)   ( cd "$HERE/rust" && cargo +stable-x86_64-pc-windows-gnu run --bin tg --release --quiet -- "$VEC" 2>/dev/null \
              || cargo run --bin tg --release --quiet -- "$VEC" ) ;;
    dotnet) ( cd "$HERE/dotnet_tg" && dotnet run -c Release --verbosity quiet -- "$VEC" ) ;;
  esac
}
echo "=== trust_gate deny-table gauntlet (8-impl) ==="
tok=0; tot=0; green=1
for lang in "${LANGS[@]}"; do
  line=$(run_lang "$lang" 2>/dev/null | grep -E "^TRUST-GATE-GAUNTLET " | tail -1)
  if [ -z "$line" ]; then printf "  %-8s ERROR\n" "$lang"; green=0; continue; fi
  frac="${line##* }"; printf "  %-8s %s\n" "$lang" "$frac"
  ok="${frac%%/*}"; n="${frac##*/}"; tok=$((tok+ok)); tot=$((tot+n)); [ "$ok" = "$n" ] || green=0
done
echo "TOTAL: ${tok}/${tot}"; [ "$green" = 1 ] && { echo "RESULT: ALL GREEN"; exit 0; } || { echo "RESULT: NOT GREEN"; exit 1; }
