#!/usr/bin/env bash
# Keystone L3 fail-closed gauntlet -- multi-implementation cross-validation.
#
# Each runner is an INDEPENDENT reimplementation of decision_audit_ref (a
# different JCS library per language) that accepts every positive, fail-closes
# on every negative, and holds both invariants (screen presence bound; malformed
# ref rejected). A single-implementation fork cannot demonstrate cross-language
# fail-closed agreement at the L3 keystone tier.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
VEC="$(cd "$HERE/../../vectors/keystone_decision_audit_v1" && pwd)/keystone_decision_audit_v1.json"
LANGS=(python node go)

run_lang() {
  case "$1" in
    python) python "$HERE/gauntlet_python.py" "$VEC" ;;
    node)   node "$HERE/gauntlet_node.mjs" "$VEC" ;;
    go)     ( cd "$HERE" && GO111MODULE=on go run gauntlet_go.go "$VEC" ) ;;
  esac
}

echo "================================================================"
echo "KEYSTONE L3 GAUNTLET -- decision_audit_ref fail-closed cross-validation"
echo "vector set: keystone_decision_audit_v1 (2 positive + 4 negative + 2 invariant)"
echo "================================================================"
total_ok=0; total=0; green=1
for lang in "${LANGS[@]}"; do
  line=$(run_lang "$lang" 2>/dev/null | grep -E "^KEYSTONE-GAUNTLET " | tail -1)
  if [ -z "$line" ]; then printf "  %-8s ERROR (toolchain?)\n" "$lang"; green=0; continue; fi
  frac="${line##* }"
  printf "  %-8s %s\n" "$lang" "$frac"
  ok="${frac%%/*}"; n="${frac##*/}"
  total_ok=$((total_ok+ok)); total=$((total+n))
  [ "$ok" = "$n" ] || green=0
done
echo "----------------------------------------------------------------"
echo "TOTAL fail-closed verdicts: ${total_ok}/${total}"
if [ "$green" = 1 ]; then
  echo "RESULT: ALL GREEN -- every impl accepts positives and fail-closes on every attack."
  exit 0
else
  echo "RESULT: NOT GREEN"
  exit 1
fi
