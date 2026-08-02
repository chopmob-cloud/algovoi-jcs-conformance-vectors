#!/usr/bin/env bash
# Differential adversarial substrate -- 10-implementation N-way consensus run.
#
# Each language's canon probe emits "<id>\t<verdict>" for every case; the driver
# then requires FULL N-way consensus on the agree/reject corpora and MAPS every
# divergence in the hazard corpus. A 2-implementation corpus (e.g. Concordia's
# Python+JS) structurally cannot express N-way cross-language consensus; this is
# the property, grounded entirely in AlgoVoi's own 10-language substrate.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="$(command -v python3 || command -v python)"
CORPORA=(cases_consensus_v1.json cases_hazard_v1.json cases_tier_v1.json)
ABS=(); for c in "${CORPORA[@]}"; do ABS+=("$HERE/$c"); done
LANGS=(python node go php ruby java rust dotnet kotlin elixir)

SEP=":"; case "$(uname -s 2>/dev/null)" in Linux|Darwin) SEP=":" ;; *) SEP=";" ;; esac

mkdir -p "$HERE/out"

# --- one-time builds for JVM langs ---
prebuild() {
  ( cd "$HERE/java" 2>/dev/null || return 0
    [ -d libs ] || cp -r "$HERE/../../vectors/retention_chain_v1/runner_java/libs" libs 2>/dev/null
    [ -f Probe.class ] && [ Probe.class -nt Probe.java ] || javac -cp "libs/*" Probe.java 2>/dev/null )
  ( cd "$HERE" 2>/dev/null || return 0
    KOTLINC="$(command -v kotlinc || echo /opt/kotlinc/bin/kotlinc)"
    CP="$(echo java/libs/*.jar | tr ' ' "$SEP")"
    [ -f kotlin/probe.jar ] && [ kotlin/probe.jar -nt kotlin/Probe.kt ] || \
      "$KOTLINC" kotlin/Probe.kt -cp "$CP" -include-runtime -d kotlin/probe.jar >/dev/null 2>&1 )
}

run_probe() { # <lang> <abs-corpus>
  case "$1" in
    python) "$PY" "$HERE/probe_python.py" "$2" ;;
    node)   node "$HERE/probe_node.mjs" "$2" ;;
    go)     ( cd "$HERE/go" && GO111MODULE=on go run probe_go.go "$2" ) ;;
    php)    php "$HERE/probe_php.php" "$2" ;;
    ruby)   ruby "$HERE/probe_ruby.rb" "$2" ;;
    java)   ( cd "$HERE/java" && java -cp ".${SEP}libs/*" Probe "$2" ) ;;
    rust)   ( cd "$HERE/rust" && cargo +stable-x86_64-pc-windows-gnu run --release --quiet -- "$2" 2>/dev/null \
              || cargo run --release --quiet -- "$2" ) ;;
    dotnet) ( cd "$HERE/dotnet" && dotnet run -c Release --verbosity quiet -- "$2" ) ;;
    kotlin) ( cd "$HERE" && java -cp "kotlin/probe.jar${SEP}java/libs/*" Probe "$2" ) ;;
    elixir) elixir "$HERE/probe_elixir.exs" "$2" ;;
  esac
}

prebuild
echo "collecting verdicts from ${#LANGS[@]} implementations..."
for lang in "${LANGS[@]}"; do
  : > "$HERE/out/$lang.txt"
  fail=0
  for c in "${ABS[@]}"; do
    run_probe "$lang" "$c" >> "$HERE/out/$lang.txt" 2>/dev/null || fail=1
  done
  n=$(grep -c . "$HERE/out/$lang.txt" 2>/dev/null || echo 0)
  if [ "$fail" = 1 ] || [ "$n" = 0 ]; then
    printf "  %-8s unavailable (toolchain?) -- excluded\n" "$lang"
    rm -f "$HERE/out/$lang.txt"
  else
    printf "  %-8s %s verdicts\n" "$lang" "$n"
  fi
done
echo
"$PY" "$HERE/differential_driver.py" --out "$HERE/out" --require "${REQUIRE:-10}" "${ABS[@]}"
