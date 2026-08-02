#!/bin/sh
# KAF cell execution. Runs INSIDE the cell container with --network=none.
# POSIX sh (busybox ash compatible). Everything here follows the real-module
# rule: suites and canaries execute as program files, never through -e/eval
# contexts, because eval contexts inject globals that mask environment defects
# (the Node 18 crypto.subtle lesson).
#
# Mounts: /corpus (ro), /cellenv (ro), /kafout (rw).
# Env: CELL_ID, CELL_LANG, CELL_SUITES (comma separated).
set -u
CELL_ID="${CELL_ID:?}"
CELL_LANG="${CELL_LANG:?}"
CELL_SUITES="${CELL_SUITES:?}"
OUT=/kafout
mkdir -p "$OUT"
: > "$OUT/suites.tsv"

VENVPY=/cellenv/venv/bin/python
[ -x "$VENVPY" ] || VENVPY="$(command -v python3 || echo /usr/bin/python3)"
export GEM_PATH=/cellenv/gems
# Elixir Mix.install resolves against the cache warmed during provisioning.
# /cellenv is mounted read-only at execution and Mix touches its cache on
# reuse, so the warmed cache is copied to writable /tmp first. The network
# stays =none: everything Mix needs is already in the copy.
if [ "$CELL_LANG" = "elixir" ]; then
  mkdir -p /tmp/kafmix
  cp -r /cellenv/mix /tmp/kafmix/mix 2>/dev/null
  cp -r /cellenv/hex /tmp/kafmix/hex 2>/dev/null
  cp -r /cellenv/.mix /tmp/kafmix/.mix 2>/dev/null
  cp -r /cellenv/.hex /tmp/kafmix/.hex 2>/dev/null
  cp -r /cellenv/.cache /tmp/kafmix/.cache 2>/dev/null
  export MIX_HOME=/tmp/kafmix/mix HEX_HOME=/tmp/kafmix/hex HOME=/tmp/kafmix
fi

# Environment fingerprint.
{
  echo "cell: $CELL_ID"
  echo "lang: $CELL_LANG"
  uname -a
  case "$CELL_LANG" in
    python) "$VENVPY" -V 2>&1 ;;
    node)   node -v 2>&1 ;;
    php)    php -v 2>&1 | head -1 ;;
    ruby)   ruby -v 2>&1 ;;
    elixir) elixir --version 2>&1 | tail -1 ;;
  esac
} > "$OUT/env.txt" 2>&1

# Network canary: a real program file that PASSES iff the network is
# unreachable. A reachable network is a hard cell failure.
CANARY_RC=-1
case "$CELL_LANG" in
  python) "$VENVPY" /corpus/kaf/net_canary.py  > "$OUT/canary.log" 2>&1; CANARY_RC=$? ;;
  node)   node      /corpus/kaf/net_canary.mjs > "$OUT/canary.log" 2>&1; CANARY_RC=$? ;;
  *)      echo "canary not defined for $CELL_LANG (docker --network=none argv recorded host-side)" > "$OUT/canary.log" ;;
esac
if [ "$CANARY_RC" -gt 0 ]; then
  echo "canary	$CANARY_RC" >> "$OUT/suites.tsv"
  echo "FATAL: network reachable inside cell $CELL_ID" >> "$OUT/canary.log"
  exit 9
fi

OVERALL=0
run_suite() { # name -> runs it, appends "name<tab>rc" to suites.tsv
  name="$1"; rc=0
  case "$name" in
    verify_corpus)
      ( cd /corpus/composition && "$VENVPY" verify_corpus.py ) > "$OUT/verify_corpus.log" 2>&1; rc=$? ;;
    first_principles)
      ( cd /corpus/composition && "$VENVPY" first_principles_check.py ) > "$OUT/first_principles.log" 2>&1; rc=$? ;;
    adversarial_jcs)
      ( cd /corpus/composition && "$VENVPY" adversarial_jcs_check.py ) > "$OUT/adversarial_jcs.log" 2>&1; rc=$? ;;
    mutation_fuzz)
      ( cd /corpus/composition && "$VENVPY" mutation_fuzz.py ) > "$OUT/mutation_fuzz.log" 2>&1; rc=$? ;;
    matrix:*)
      lang="${name#matrix:}"
      KAF_PY="$VENVPY" sh /corpus/kaf/run_matrix_lang.sh "$lang" /corpus \
        > "$OUT/matrix_$lang.tsv" 2> "$OUT/matrix_$lang.log"; rc=$? ;;
    *)
      echo "unknown suite $name" > "$OUT/unknown_suite.log"; rc=97 ;;
  esac
  printf '%s\t%s\n' "$name" "$rc" >> "$OUT/suites.tsv"
  [ "$rc" -ne 0 ] && OVERALL=1
  return 0
}

REST="$CELL_SUITES,"
while [ -n "$REST" ]; do
  cur="${REST%%,*}"; REST="${REST#*,}"
  [ -n "$cur" ] && run_suite "$cur"
done

echo "overall	$OVERALL" >> "$OUT/suites.tsv"
exit "$OVERALL"
