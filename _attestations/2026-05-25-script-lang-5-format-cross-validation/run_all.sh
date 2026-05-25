#!/usr/bin/env bash
# run_all.sh -- run 5 scripting-language JCS impls against the 5
# AlgoVoi-authored receipt/response format vector sets.
#
# 5 impls × 5 vector sets × 8 vectors each = 200 byte-for-byte
# comparisons.
#
# Pre-requisites:
#   pip install algovoi-substrate>=0.3.0
#   cd this dir; npm init -y; npm install @algovoi/substrate@^0.3.0
#   gem install json-canonicalization
#   php 8.1+ (no extra packages; inline JCS)
#   go 1.20+ (gowebpki/jcs auto-fetched via go mod)
set -u
cd "$(dirname "$0")"

VECTOR_SETS=(
  "compliance_receipt_v1"
  "settlement_attestation_v1"
  "cancellation_receipt_v1"
  "refund_receipt_v1"
  "composite_trust_query_v1"
)

LANGS=(
  "python:runner_python.py"
  "node:runner_node.js"
  "ruby:runner_ruby.rb"
  "php:runner_php.php"
  "go:runner_go.go"
)

declare -A RESULTS
TOTAL_PASS=0
TOTAL_FAIL=0

for set_id in "${VECTOR_SETS[@]}"; do
  vector_file="../../vectors/$set_id/${set_id}.json"
  echo
  echo "================================================================"
  echo "Vector set: $set_id"
  echo "================================================================"
  for entry in "${LANGS[@]}"; do
    lang="${entry%%:*}"
    runner="${entry#*:}"
    case "$lang" in
      python) cmd=(python "$runner" "$vector_file") ;;
      node) cmd=(node "$runner" "$vector_file") ;;
      ruby) cmd=(ruby "$runner" "$vector_file") ;;
      php) cmd=(php "$runner" "$vector_file") ;;
      go) cmd=(go run "$runner" "$vector_file") ;;
    esac
    echo "--- $lang ---"
    output=$("${cmd[@]}" 2>&1 | tail -1)
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
for entry in "${LANGS[@]}"; do
  printf " | %-7s" "${entry%%:*}"
done
echo
for set_id in "${VECTOR_SETS[@]}"; do
  printf "%-30s" "$set_id"
  for entry in "${LANGS[@]}"; do
    lang="${entry%%:*}"
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
