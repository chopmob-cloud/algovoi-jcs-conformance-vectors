#!/bin/sh
# KAF cell provisioning. Runs INSIDE the cell container WITH network, as the
# recorded exception to the hermetic contract: dependencies are fetched here,
# written to the /cellenv volume, and the exact outcome (installed set, any
# per-package failure) is recorded to /cellenv/provision.json so the sealed
# receipt can attribute every bit that later executes offline.
#
# Mounts: /corpus (ro), /cellenv (rw). Env: CELL_ID, CELL_LANG.
set -u
CELL_ID="${CELL_ID:?}"
CELL_LANG="${CELL_LANG:?}"
mkdir -p /cellenv

note() { echo "[provision:$CELL_ID] $*"; }

# Best-effort build tools for source builds (musl wheels gaps, native gems).
# Failure is tolerated and recorded; pure wheels do not need them.
TOOLS_RC=0
if command -v apk >/dev/null 2>&1; then
  apk add --no-cache build-base libffi-dev python3-dev ca-certificates >/dev/null 2>&1 || TOOLS_RC=$?
elif command -v apt-get >/dev/null 2>&1; then
  ( apt-get update >/dev/null 2>&1 && \
    apt-get install -y --no-install-recommends build-essential libffi-dev ca-certificates >/dev/null 2>&1 ) || TOOLS_RC=$?
fi

FAILED=""
case "$CELL_LANG" in
  python)
    python3 -m venv /cellenv/venv || { note "venv creation failed"; exit 3; }
    PIP=/cellenv/venv/bin/pip
    "$PIP" install --no-cache-dir -q -U pip >/dev/null 2>&1
    # composition/requirements.txt is the corpus source of truth; rfc8785 backs
    # adversarial_jcs_check; algovoi-execution-ref backs execution_ref_v1.
    for spec in \
      "algovoi-substrate==0.4.0" \
      "PyNaCl>=1.5.0" \
      "pqcrypto>=0.3.4" \
      "algovoi-rfc9421-verifier" \
      "algovoi-rfc9421-signer" \
      "rfc8785" \
      "cryptography" \
      "algovoi-execution-ref"; do
      if ! "$PIP" install --no-cache-dir -q "$spec" >/dev/null 2>&1; then
        note "install failed (recorded, tolerated): $spec"
        FAILED="$FAILED $spec"
      fi
    done
    "$PIP" freeze > /cellenv/freeze.txt 2>/dev/null
    ;;
  ruby)
    for g in ed25519 json-canonicalization; do
      gem install "$g" --no-document --install-dir /cellenv/gems >/dev/null 2>&1 || {
        note "gem install $g failed (recorded)"; FAILED="$FAILED $g(gem)"; }
    done
    ;;
  elixir)
    # Runners that use Mix.install fetch hex packages at first run. Warm every
    # elixir runner's install cache now (network phase) into /cellenv so the
    # offline execution phase hits only the cache.
    export MIX_HOME=/cellenv/mix HEX_HOME=/cellenv/hex HOME=/cellenv
    mkdir -p "$MIX_HOME" "$HEX_HOME"
    mix local.hex --force >/dev/null 2>&1
    mix local.rebar --force >/dev/null 2>&1
    for r in /corpus/vectors/*/runner_elixir.exs; do
      [ -f "$r" ] || continue
      d=$(dirname "$r"); s=$(basename "$d")
      j="$s.json"
      if [ ! -f "$d/$j" ]; then
        j=$(ls "$d"/*.json 2>/dev/null | grep -viE 'schema|manifest|expected|package|tsconfig' | head -1)
        [ -n "$j" ] && j=$(basename "$j")
      fi
      ( cd "$d" && timeout 300 elixir "$(basename "$r")" "$j" >/dev/null 2>&1 ) || {
        note "elixir warm failed (recorded): $s"; FAILED="$FAILED $s(elixir-warm)"; }
    done
    ;;
  go)
    # Warm the module cache for every go runner set so execution can build
    # with GOPROXY=off. The build cache stays cold at exec (writable /tmp).
    # Use `go mod download` (NOT `all`): the main-module deps are fully pinned
    # in each committed go.sum, so this needs no go.sum write, whereas
    # `download all` reaches into dependencies' test deps whose hashes are not
    # in our go.sum and then fails writing go.sum into the read-only /corpus.
    export GOMODCACHE=/cellenv/gomod GOPATH=/cellenv/go GOCACHE=/tmp/gocache
    mkdir -p "$GOMODCACHE" "$GOPATH"
    for m in /corpus/vectors/*/go.mod; do
      [ -f "$m" ] || continue
      d=$(dirname "$m"); s=$(basename "$d")
      ( cd "$d" && timeout 300 go mod download >/dev/null 2>&1 ) || {
        note "go mod download failed (recorded): $s"; FAILED="$FAILED $s(gomod)"; }
    done
    ;;
  node|php)
    # Nothing to provision: node sets vendor node_modules in-tree; php
    # runners are stdlib-only.
    ;;
  *)
    note "no provisioning defined for lang $CELL_LANG"
    ;;
esac

# Machine-readable record (python3 if present for correct JSON, else printf).
if command -v python3 >/dev/null 2>&1; then
  FAILED="$FAILED" CELL_ID="$CELL_ID" CELL_LANG="$CELL_LANG" TOOLS_RC="$TOOLS_RC" \
  python3 - <<'EOF'
import json, os, platform
rec = {
    "cell": os.environ["CELL_ID"],
    "lang": os.environ["CELL_LANG"],
    "network": "on (provisioning phase, recorded exception)",
    "build_tools_rc": int(os.environ.get("TOOLS_RC", "0")),
    "failed_specs": os.environ.get("FAILED", "").split(),
    "platform": platform.platform(),
}
try:
    with open("/cellenv/freeze.txt", encoding="utf-8") as f:
        rec["freeze"] = f.read().splitlines()
except OSError:
    pass
with open("/cellenv/provision.json", "w", encoding="utf-8") as f:
    json.dump(rec, f, indent=1, sort_keys=True)
EOF
else
  printf '{"cell":"%s","lang":"%s","failed_specs":"%s"}\n' \
    "$CELL_ID" "$CELL_LANG" "$FAILED" > /cellenv/provision.json
fi
note "done (failed_specs:${FAILED:-none})"
exit 0
