#!/usr/bin/env bash
# revocation_ref fail-closed gauntlet -- 8-implementation cross-validation.
# Independent reimplementations of revocation_ref + verify_revocation_chain
# (substrate2/keystone_secure.py): every impl reproduces valid link refs, fail-
# closes on malformed revocations, detects tampered claims, and rejects broken/
# reordered/bad-genesis chains.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
VEC="$(cd "$HERE/../../vectors/revocation_ref_v1" && pwd)/revocation_ref_v1.json"
LANGS=(python node go php ruby java rust dotnet)
SEP=";"; case "$(uname -s 2>/dev/null)" in Linux|Darwin) SEP=":" ;; esac
run_lang() {
  case "$1" in
    python) "$(command -v python3 || command -v python)" "$HERE/rev_python.py" "$VEC" ;;
    node)   node "$HERE/rev_node.mjs" "$VEC" ;;
    go)     ( cd "$HERE" && GO111MODULE=on go run rev_go.go "$VEC" ) ;;
    php)    php "$HERE/rev_php.php" "$VEC" ;;
    ruby)   ruby "$HERE/rev_ruby.rb" "$VEC" ;;
    java)   ( cd "$HERE/java"
              [ -d libs ] || cp -r "$HERE/../../vectors/retention_chain_v1/runner_java/libs" libs
              [ -f RevRunner.class ] && [ RevRunner.class -nt RevRunner.java ] || javac -cp "libs/*" RevRunner.java
              java -cp ".${SEP}libs/*" RevRunner "$VEC" ) ;;
    rust)   ( cd "$HERE/rust" && cargo +stable-x86_64-pc-windows-gnu run --bin rev --release --quiet -- "$VEC" 2>/dev/null \
              || cargo run --bin rev --release --quiet -- "$VEC" ) ;;
    dotnet) ( cd "$HERE/dotnet_rev" && dotnet run -c Release --verbosity quiet -- "$VEC" ) ;;
  esac
}
echo "=== revocation_ref fail-closed gauntlet (8-impl) ==="
tok=0; tot=0; green=1
for lang in "${LANGS[@]}"; do
  line=$(run_lang "$lang" 2>/dev/null | grep -E "^REVOCATION-GAUNTLET " | tail -1)
  if [ -z "$line" ]; then printf "  %-8s ERROR\n" "$lang"; green=0; continue; fi
  frac="${line##* }"; printf "  %-8s %s\n" "$lang" "$frac"
  ok="${frac%%/*}"; n="${frac##*/}"; tok=$((tok+ok)); tot=$((tot+n)); [ "$ok" = "$n" ] || green=0
done
echo "TOTAL: ${tok}/${tot}"; [ "$green" = 1 ] && { echo "RESULT: ALL GREEN"; exit 0; } || { echo "RESULT: NOT GREEN"; exit 1; }
