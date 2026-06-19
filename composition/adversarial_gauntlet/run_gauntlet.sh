#!/usr/bin/env bash
# Adversarial gauntlet -- 8-implementation FAIL-CLOSED cross-validation.
#
# Positive cross-validation (832/832) proves 8 impls AGREE on valid inputs.
# This proves the harder claim: 8 independent implementations all REJECT every
# adversarial mutation and ACCEPT the control, identically. 8 impls x 12 vectors
# = 96 fail-closed verdicts. A single-implementation fork cannot demonstrate this.
#
# Each runner is an independent reimplementation of the three substrate-1 checks
# (transition_preimage, action_ref, audit_chain) -- no algovoi import.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
VEC="$(cd "$HERE/../../vectors/adversarial_isolation_v1" && pwd)/adversarial_isolation_v1.json"
LANGS=(python node ruby php go rust java dotnet)

run_lang() {
  case "$1" in
    python) python "$HERE/gauntlet_python.py" "$VEC" ;;
    node)   node "$HERE/gauntlet_node.js" "$VEC" ;;
    ruby)   ruby "$HERE/gauntlet_ruby.rb" "$VEC" ;;
    php)    php "$HERE/gauntlet_php.php" "$VEC" ;;
    go)     ( cd "$HERE" && GO111MODULE=off go run gauntlet_go.go "$VEC" ) ;;
    rust)   ( cd "$HERE/rust" && cargo +stable-x86_64-pc-windows-gnu run --release --quiet -- "$VEC" ) ;;
    java)   ( cd "$HERE/java" && java -cp ".;libs/*" Runner "$VEC" ) ;;
    dotnet) ( cd "$HERE/dotnet" && dotnet run -c Release --verbosity quiet -- "$VEC" ) ;;
  esac
}

# one-time java compile if needed
if [ ! -f "$HERE/java/Runner.class" ] || [ "$HERE/java/Runner.java" -nt "$HERE/java/Runner.class" ]; then
  ( cd "$HERE/java" && javac -cp "libs/*" Runner.java )
fi

TOTAL_OK=0
TOTAL=0
declare -A PER
for lang in "${LANGS[@]}"; do
  line=$(run_lang "$lang" 2>/dev/null | grep -E "^GAUNTLET " | tail -1)
  if [ -z "$line" ]; then PER["$lang"]="ERROR"; continue; fi
  frac="${line##* }"          # X/Y
  ok="${frac%/*}"; tot="${frac#*/}"
  PER["$lang"]="$frac"
  TOTAL_OK=$((TOTAL_OK + ok))
  TOTAL=$((TOTAL + tot))
done

echo "================================================================"
echo "ADVERSARIAL GAUNTLET -- 8-impl fail-closed cross-validation"
echo "vector set: adversarial_isolation_v1 (1 control + 11 isolated rejections)"
echo "================================================================"
for lang in "${LANGS[@]}"; do printf "  %-8s %s\n" "$lang" "${PER[$lang]:-MISSING}"; done
echo "----------------------------------------------------------------"
echo "TOTAL fail-closed verdicts: ${TOTAL_OK}/${TOTAL}"
[ "$TOTAL_OK" -eq "$TOTAL" ] && [ "$TOTAL" -gt 0 ] && { echo "RESULT: ALL GREEN -- every impl accepts the control and rejects all 11 attacks."; exit 0; }
echo "RESULT: NOT ALL GREEN -- investigate."; exit 1
