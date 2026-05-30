#!/usr/bin/env bash
# run_all.sh -- 8 JCS impls x pef_v1 vector set (8 vectors)
# = 64 byte-for-byte comparisons (16 per vector: receipt_hash + frame_id)
#
# Usage: bash run_all.sh
set -u
cd "$(dirname "$0")"
HERE="$(pwd -W 2>/dev/null || pwd)"

VECTOR_FILE="$(cd ../../vectors/pef_v1 && pwd -W 2>/dev/null || pwd)/pef_v1.json"

LANGS=(python node ruby php go rust java dotnet)
declare -A RESULTS
TOTAL_PASS=0
TOTAL_FAIL=0

run_lang() {
  local lang="$1"
  case "$lang" in
    python) python runner_python.py "$VECTOR_FILE" ;;
    node)   node runner_node.js "$VECTOR_FILE" ;;
    ruby)   ruby runner_ruby.rb "$VECTOR_FILE" ;;
    php)    php runner_php.php "$VECTOR_FILE" ;;
    go)     go run runner_go.go "$VECTOR_FILE" ;;
    rust)
      ( cd runner_rust && cargo +stable-x86_64-pc-windows-gnu run --release --quiet -- "$VECTOR_FILE" )
      ;;
    java)
      ( cd runner_java && java -cp ".;libs/*" Runner "$VECTOR_FILE" )
      ;;
    dotnet)
      ( cd runner_dotnet && dotnet run -c Release --verbosity quiet -- "$VECTOR_FILE" )
      ;;
  esac
}

echo
echo "================================================================"
echo "PEF v1 -- 8-impl cross-validation -- $(date -u +%Y-%m-%d)"
echo "Vector file: $VECTOR_FILE"
echo "================================================================"

for lang in "${LANGS[@]}"; do
  echo "--- $lang ---"
  output=$(run_lang "$lang" 2>&1 | tail -1)
  echo "$output"
  RESULTS["$lang"]="$output"
  if echo "$output" | grep -qE "^[0-9]+/[0-9]+ PASS$"; then
    p=${output%/*}
    t=${output#*/}; t=${t% PASS}
    TOTAL_PASS=$((TOTAL_PASS + p))
    TOTAL_FAIL=$((TOTAL_FAIL + t - p))
  else
    TOTAL_FAIL=$((TOTAL_FAIL + 8))
  fi
done

echo
echo "================================================================"
echo "FULL MATRIX"
echo "================================================================"
printf "%-12s | %s\n" "Lang" "Result"
echo "-------------|--------"
for lang in "${LANGS[@]}"; do
  printf "%-12s | %s\n" "$lang" "${RESULTS[$lang]}"
done

echo
echo "================================================================"
echo "Total: $TOTAL_PASS PASS / $TOTAL_FAIL FAIL"
echo "================================================================"

if [ "$TOTAL_FAIL" -gt 0 ]; then exit 1; fi
exit 0
