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
  apk add --no-cache build-base libffi-dev python3-dev >/dev/null 2>&1 || TOOLS_RC=$?
elif command -v apt-get >/dev/null 2>&1; then
  ( apt-get update >/dev/null 2>&1 && \
    apt-get install -y --no-install-recommends build-essential libffi-dev >/dev/null 2>&1 ) || TOOLS_RC=$?
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
      "algovoi-execution-ref"; do
      if ! "$PIP" install --no-cache-dir -q "$spec" >/dev/null 2>&1; then
        note "install failed (recorded, tolerated): $spec"
        FAILED="$FAILED $spec"
      fi
    done
    "$PIP" freeze > /cellenv/freeze.txt 2>/dev/null
    ;;
  ruby)
    gem install ed25519 --no-document --install-dir /cellenv/gems >/dev/null 2>&1 || {
      note "gem install ed25519 failed (recorded)"; FAILED="$FAILED ed25519(gem)"; }
    ;;
  node|php|elixir)
    # Nothing to provision: node sets vendor node_modules in-tree; php and
    # elixir runners are stdlib-only.
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
