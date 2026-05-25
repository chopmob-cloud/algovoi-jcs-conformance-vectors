#!/usr/bin/env bash
# run_all.sh -- run 8 JCS impls against the 5 AlgoVoi-authored
# receipt/response format vector sets.
#
# 8 impls x 5 vector sets x 8 vectors each = 320 byte-for-byte
# comparisons.
set -u
cd "$(dirname "$0")"
HERE="$(pwd -W 2>/dev/null || pwd)"

VECTOR_SETS=(
  "compliance_receipt_v1"
  "settlement_attestation_v1"
  "cancellation_receipt_v1"
  "refund_receipt_v1"
  "composite_trust_query_v1"
)

run_lang() {
  local lang="$1" vector="$2"
  case "$lang" in
    python) python runner_python.py "$vector" ;;
    node) node runner_node.js "$vector" ;;
    ruby) ruby runner_ruby.rb "$vector" ;;
    php) php runner_php.php "$vector" ;;
    go) go run runner_go.go "$vector" ;;
    rust)
      ( cd runner_rust && cargo +stable-x86_64-pc-windows-gnu run --release --quiet -- "$vector" )
      ;;
    java)
      ( cd runner_java && java -cp ".;libs/*" Runner "$vector" )
      ;;
    dotnet)
      ( cd runner_dotnet && dotnet run -c Release --verbosity quiet -- "$vector" )
      ;;
  esac
}

LANGS=(python node ruby php go rust java dotnet)
declare -A RESULTS
TOTAL_PASS=0
TOTAL_FAIL=0

for set_id in "${VECTOR_SETS[@]}"; do
  vector_file="$(cd ../../vectors/$set_id && pwd -W 2>/dev/null || pwd)/${set_id}.json"
  echo
  echo "================================================================"
  echo "Vector set: $set_id"
  echo "================================================================"
  for lang in "${LANGS[@]}"; do
    echo "--- $lang ---"
    output=$(run_lang "$lang" "$vector_file" 2>&1 | tail -1)
    echo "$output"
    RESULTS["$set_id|$lang"]="$output"
    if echo "$output" | grep -q "^[0-9]*/[0-9]* PASS$"; then
      pass=${output%/*}
      total=${output#*/}
      total=${total% PASS}
      TOTAL_PASS=$((TOTAL_PASS + pass))
      TOTAL_FAIL=$((TOTAL_FAIL + total - pass))
    else
      TOTAL_FAIL=$((TOTAL_FAIL + 8))
    fi
  done
done

echo
echo "================================================================"
echo "FULL MATRIX"
echo "================================================================"
printf "%-30s" "Vector set / lang"
for lang in "${LANGS[@]}"; do
  printf " | %-7s" "$lang"
done
echo
for set_id in "${VECTOR_SETS[@]}"; do
  printf "%-30s" "$set_id"
  for lang in "${LANGS[@]}"; do
    printf " | %-7s" "${RESULTS[$set_id|$lang]}"
  done
  echo
done
echo
echo "================================================================"
echo "Total: $TOTAL_PASS PASS / $TOTAL_FAIL FAIL"
echo "================================================================"

if [ "$TOTAL_FAIL" -gt 0 ]; then exit 1; fi
exit 0
