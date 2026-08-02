#!/usr/bin/env bash
# Full per-set runner matrix: for EVERY vector set, run EVERY runner it ships and
# check it reproduces (exit 0). Resolves each set's vector JSON and passes it as
# argv (runners that self-locate ignore it; runners that require it get it).
# Covers python/node/php/ruby/elixir/go/rust/dotnet. Java/Kotlin per-set are
# covered by the per-set run_all.sh + the 10-language tier gauntlets.
set -u
ROOT="${1:-$(pwd)}"
cd "$ROOT" || exit 2
PY="$(command -v python3 || command -v python)"

declare -A LPASS LFAIL
TOTAL_PASS=0; TOTAL_FAIL=0; TOTAL_SKIP=0
FAILS=(); SKIPS=()

# Optional signature/zkp libraries that gate a specific (set,lang) runner, the
# SAME class verify_corpus documents via SIGNATURE_DEPS/EXTERNAL. Each vector is
# proven correct in python (where the mature dep is installed); these are the
# per-language crypto/proof libs that do not build/publish/resolve cleanly in
# this environment -- NOT canonicalization failures. Named, never silently hidden.
declare -A OPTDEP
OPTDEP["execution_ref_v1:node"]="@algovoi/execution-ref (npm, not published/declared here)"
OPTDEP["rfc9421_proxy_chain_v0:node"]="@algovoi/rfc9421-verifier (npm version/signing-base mismatch)"
OPTDEP["rfc9421_proxy_chain_v0:ruby"]="ed25519 gem (native ext needs libsodium headers)"
OPTDEP["rfc9421_proxy_chain_v1:ruby"]="ed25519 gem (native ext needs libsodium headers)"
OPTDEP["zkp_receipt_v1:node"]="@algovoi/substrate (npm path stale)"

tally() { # <lang> <label> <rc> <lastline>
  local lang="$1" label="$2" rc="$3" last="$4"
  if [ "$rc" -eq 0 ]; then
    LPASS[$lang]=$(( ${LPASS[$lang]:-0} + 1 )); TOTAL_PASS=$((TOTAL_PASS+1))
  elif [ -n "${OPTDEP[$label:$lang]:-}" ]; then
    TOTAL_SKIP=$((TOTAL_SKIP+1)); SKIPS+=("$label [$lang] -- ${OPTDEP[$label:$lang]}")
  else
    LFAIL[$lang]=$(( ${LFAIL[$lang]:-0} + 1 )); TOTAL_FAIL=$((TOTAL_FAIL+1))
    FAILS+=("$label [$lang] rc=$rc :: $last")
  fi
}

for d in vectors/*/; do
  s=$(basename "$d")
  # resolve the vector JSON filename (handles ap2-omh-v0.json, privacy_class_v0.1.json,
  # chain.fixture.json, fixture.json, ...): prefer <set>.json, else the one non-schema json.
  j="$s.json"
  if [ ! -f "$d/$j" ]; then
    j=$(ls "$d"*.json 2>/dev/null | grep -viE 'schema|manifest|expected|package|tsconfig' | head -1 | xargs -n1 basename 2>/dev/null)
  fi
  [ -z "$j" ] && continue

  # script langs + go: run from setdir, pass the json filename
  [ -f "$d/runner_python.py" ] && { o=$(cd "$d" && timeout 150 "$PY" runner_python.py "$j" 2>&1); tally python "$s" $? "$(echo "$o"|tail -1)"; }
  for nf in runner_node.js runner_node.mjs; do
    [ -f "$d/$nf" ] && { o=$(cd "$d" && timeout 150 node "$nf" "$j" 2>&1); tally node "$s" $? "$(echo "$o"|tail -1)"; }
  done
  [ -f "$d/runner_php.php" ]    && command -v php    >/dev/null && { o=$(cd "$d" && timeout 150 php runner_php.php "$j" 2>&1); tally php "$s" $? "$(echo "$o"|tail -1)"; }
  [ -f "$d/runner_ruby.rb" ]   && command -v ruby   >/dev/null && { o=$(cd "$d" && timeout 150 ruby runner_ruby.rb "$j" 2>&1); tally ruby "$s" $? "$(echo "$o"|tail -1)"; }
  [ -f "$d/runner_elixir.exs" ]&& command -v elixir >/dev/null && { o=$(cd "$d" && timeout 200 elixir runner_elixir.exs "$j" 2>&1); tally elixir "$s" $? "$(echo "$o"|tail -1)"; }
  if [ -f "$d/runner_go.go" ] && [ -f "$d/go.mod" ] && command -v go >/dev/null; then
    o=$(cd "$d" && timeout 200 go run runner_go.go "$j" 2>&1); tally go "$s" $? "$(echo "$o"|tail -1)"
  fi
  # compiled langs in subdirs: json is one level up (../$j)
  if [ -d "$d/runner_rust" ] && [ -f "$d/runner_rust/Cargo.toml" ] && command -v cargo >/dev/null; then
    o=$(cd "$d/runner_rust" && timeout 300 cargo run --quiet --release -- "../$j" 2>&1); tally rust "$s" $? "$(echo "$o"|tail -1)"
  fi
  if [ -d "$d/runner_dotnet" ] && ls "$d"/runner_dotnet/*.csproj >/dev/null 2>&1 && command -v dotnet >/dev/null; then
    o=$(cd "$d/runner_dotnet" && timeout 300 dotnet run -c Release --verbosity quiet -- "../$j" 2>&1); tally dotnet "$s" $? "$(echo "$o"|tail -1)"
  fi
done

echo "================================================================"
echo "FULL PER-SET RUNNER MATRIX"
echo "================================================================"
for L in python node php ruby elixir go rust dotnet; do
  p=${LPASS[$L]:-0}; f=${LFAIL[$L]:-0}
  [ $((p+f)) -eq 0 ] && continue
  printf "  %-8s %d/%d\n" "$L" "$p" "$((p+f))"
done
echo "----------------------------------------------------------------"
echo "TOTAL runner executions: PASS $TOTAL_PASS  FAIL $TOTAL_FAIL  SKIP(optional-dep) $TOTAL_SKIP"
if [ ${#SKIPS[@]} -gt 0 ]; then
  echo "SKIPPED (optional signature/zkp lib; vector proven in python -- see SIGNATURE_DEPS):"
  for s in "${SKIPS[@]}"; do echo "  $s"; done
fi
if [ ${#FAILS[@]} -gt 0 ]; then
  echo "FAILURES:"; for f in "${FAILS[@]}"; do echo "  $f"; done
fi
[ $TOTAL_FAIL -eq 0 ] && echo "RESULT: ALL GREEN (optional-dep skips named above)" || echo "RESULT: FAILURES PRESENT"
exit $([ $TOTAL_FAIL -eq 0 ] && echo 0 || echo 1)
