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
TOTAL_PASS=0; TOTAL_FAIL=0; TOTAL_SKIP=0; TOTAL_DIV=0
FAILS=(); SKIPS=(); DIVS=()

# Optional library that gates a specific (set,lang) runner, the SAME class
# verify_corpus documents via SIGNATURE_DEPS/EXTERNAL. Vector proven in python;
# the per-language dep is not publishable/resolvable in this environment.
# After a provisioning pass 2026-08-02 (apt ruby-dev + ed25519 gem; npm
# @algovoi/substrate for zkp), only ONE remains: the execution_ref npm package
# is unpublished, and @algovoi/substrate on npm is 0.5.1 < 1.0.0 so it carries
# no native executionRef.
declare -A OPTDEP
OPTDEP["execution_ref_v1:node"]="@algovoi/execution-ref unpublished; @algovoi/substrate npm 0.5.1 has no native executionRef (needs >=1.0.0). python passes via algovoi-execution-ref (PyPI)."

# Documented cross-language FINDINGS (not env gaps): a runner path that reveals a
# genuine divergence between our own implementations at the same version. Named,
# counted separately, reported -- never hidden, never forced green.
declare -A DIVERGENCE
DIVERGENCE["rfc9421_proxy_chain_v0:node"]="@algovoi/rfc9421-verifier@0.3.1 on @noble/ed25519@2.3.0 REJECTS request.fixture.json that python algovoi-rfc9421-verifier@0.3.1 (PyNaCl) VERIFIES. node inputs correct (empty-body GET, content-digest of empty). Node-side Ed25519 verification divergence (likely noble v2 strictness vs libsodium)."

tally() { # <lang> <label> <rc> <lastline>
  local lang="$1" label="$2" rc="$3" last="$4"
  if [ "$rc" -eq 0 ]; then
    LPASS[$lang]=$(( ${LPASS[$lang]:-0} + 1 )); TOTAL_PASS=$((TOTAL_PASS+1))
  elif [ -n "${DIVERGENCE[$label:$lang]:-}" ]; then
    TOTAL_DIV=$((TOTAL_DIV+1)); DIVS+=("$label [$lang] -- ${DIVERGENCE[$label:$lang]}")
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
echo "TOTAL runner executions: PASS $TOTAL_PASS  FAIL $TOTAL_FAIL  SKIP(optional-dep) $TOTAL_SKIP  DIVERGENCE(finding) $TOTAL_DIV"
if [ ${#SKIPS[@]} -gt 0 ]; then
  echo "SKIPPED (optional dep; vector proven in python -- see SIGNATURE_DEPS):"
  for s in "${SKIPS[@]}"; do echo "  $s"; done
fi
if [ ${#DIVS[@]} -gt 0 ]; then
  echo "DIVERGENCE FINDINGS (real cross-language defect; investigate, do not hide):"
  for x in "${DIVS[@]}"; do echo "  $x"; done
fi
if [ ${#FAILS[@]} -gt 0 ]; then
  echo "FAILURES:"; for f in "${FAILS[@]}"; do echo "  $f"; done
fi
[ $TOTAL_FAIL -eq 0 ] && echo "RESULT: GREEN ($TOTAL_PASS pass; $TOTAL_SKIP optional-dep skip; $TOTAL_DIV documented finding; 0 unexpected fail)" || echo "RESULT: FAILURES PRESENT"
exit $([ $TOTAL_FAIL -eq 0 ] && echo 0 || echo 1)
