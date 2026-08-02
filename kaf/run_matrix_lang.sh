#!/bin/sh
# KAF single-language per-set runner matrix (POSIX sh: runs on busybox ash and
# dash inside hermetic cells). Semantics mirror composition/run_full_matrix.sh
# for the one language requested: for every vector set, run that language's
# runner and require exit 0. The optional-dep skip class is preserved verbatim.
#
# Usage: sh kaf/run_matrix_lang.sh <python|node|php|ruby|elixir|go> [corpus_root]
# Env:   KAF_PY  interpreter for python runners (defaults to python3), so a
#        provisioned virtualenv propagates to runners exactly like
#        verify_corpus.py propagates sys.executable.
# Output: TSV lines "SET<tab>LANG<tab>rc" on stdout (machine parse), human
#        summary on stderr. Exit 0 iff no unexpected failure.
set -u
LANG_REQ="${1:?usage: run_matrix_lang.sh <lang> [root]}"
ROOT="${2:-$(pwd)}"
cd "$ROOT" || exit 2
PY="${KAF_PY:-$(command -v python3 || command -v python)}"

PASS=0; FAIL=0; SKIP=0
FAILLIST=""

# The one documented optional-dep gate, same as run_full_matrix.sh:
# execution_ref_v1[node] needs an unpublished npm package; python proves the
# vector. A skip here is counted and named, never silent.
optdep() { # set lang -> 0 if this (set,lang) is a declared optional-dep skip
  [ "$1" = "execution_ref_v1" ] && [ "$2" = "node" ] && return 0
  return 1
}

tally() { # set rc
  s="$1"; rc="$2"
  printf '%s\t%s\t%s\n' "$s" "$LANG_REQ" "$rc"
  if [ "$rc" -eq 0 ]; then
    PASS=$((PASS+1))
  elif optdep "$s" "$LANG_REQ"; then
    SKIP=$((SKIP+1))
  else
    FAIL=$((FAIL+1)); FAILLIST="$FAILLIST $s"
  fi
}

for d in vectors/*/; do
  s=$(basename "$d")
  j="$s.json"
  if [ ! -f "$d/$j" ]; then
    j=$(ls "$d"*.json 2>/dev/null | grep -viE 'schema|manifest|expected|package|tsconfig' | head -1)
    [ -n "$j" ] && j=$(basename "$j")
  fi
  [ -z "$j" ] && continue

  case "$LANG_REQ" in
    python)
      [ -f "$d/runner_python.py" ] || continue
      ( cd "$d" && timeout 150 "$PY" runner_python.py "$j" >/dev/null 2>&1 ); tally "$s" $? ;;
    node)
      rn=""
      [ -f "$d/runner_node.js" ] && rn="runner_node.js"
      [ -z "$rn" ] && [ -f "$d/runner_node.mjs" ] && rn="runner_node.mjs"
      [ -z "$rn" ] && continue
      ( cd "$d" && timeout 150 node "$rn" "$j" >/dev/null 2>&1 ); tally "$s" $? ;;
    php)
      [ -f "$d/runner_php.php" ] || continue
      ( cd "$d" && timeout 150 php runner_php.php "$j" >/dev/null 2>&1 ); tally "$s" $? ;;
    ruby)
      [ -f "$d/runner_ruby.rb" ] || continue
      ( cd "$d" && timeout 150 ruby runner_ruby.rb "$j" >/dev/null 2>&1 ); tally "$s" $? ;;
    elixir)
      [ -f "$d/runner_elixir.exs" ] || continue
      ( cd "$d" && timeout 200 elixir runner_elixir.exs "$j" >/dev/null 2>&1 ); tally "$s" $? ;;
    go)
      { [ -f "$d/runner_go.go" ] && [ -f "$d/go.mod" ]; } || continue
      ( cd "$d" && timeout 200 go run runner_go.go "$j" >/dev/null 2>&1 ); tally "$s" $? ;;
    *)
      echo "unknown lang: $LANG_REQ" >&2; exit 2 ;;
  esac
done

echo "MATRIX[$LANG_REQ]: pass=$PASS fail=$FAIL skip=$SKIP${FAILLIST:+ failed:$FAILLIST}" >&2
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
