#!/usr/bin/env bash
# KAF host-side single-cell runner (VM2). Provisions with network ON (recorded
# exception), then executes with --network=none. Records the exact docker argv
# used for both phases as provenance.
#
# Usage: run_cell.sh <cell_id> <image> <lang> <suites_csv> <rundir> <corpus_dir>
set -u
CELL_ID="${1:?}"; IMAGE="${2:?}"; LANG_="${3:?}"; SUITES="${4:?}"
RUNDIR="${5:?}"; CORPUS="${6:?}"

CELLENV="$RUNDIR/cellenv/$CELL_ID"
OUT="$RUNDIR/results/$CELL_ID"
mkdir -p "$CELLENV" "$OUT"

log() { echo "[$CELL_ID] $*"; }

PROV_RC=0
case "$LANG_" in
  python|ruby)
    PARGS=(docker run --rm --name "kaf-prov-$CELL_ID"
      -e "CELL_ID=$CELL_ID" -e "CELL_LANG=$LANG_"
      -v "$CORPUS:/corpus:ro" -v "$CELLENV:/cellenv"
      "$IMAGE" sh /corpus/kaf/provision_cell.sh)
    printf '%q ' "${PARGS[@]}" > "$OUT/docker_argv_provision.txt"; echo >> "$OUT/docker_argv_provision.txt"
    "${PARGS[@]}" > "$OUT/provision.log" 2>&1; PROV_RC=$?
    echo "$PROV_RC" > "$OUT/provision.rc"
    if [ "$LANG_" = "python" ] && [ "$PROV_RC" -ne 0 ]; then
      log "provisioning failed rc=$PROV_RC (python cell cannot execute)"
      echo "overall	$PROV_RC" > "$OUT/suites.tsv"
      exit "$PROV_RC"
    fi
    cp "$CELLENV/provision.json" "$OUT/provision.json" 2>/dev/null || true
    ;;
  *) echo "none" > "$OUT/provision.rc" ;;
esac

EARGS=(docker run --rm --name "kaf-exec-$CELL_ID" --network=none
  -e "CELL_ID=$CELL_ID" -e "CELL_LANG=$LANG_" -e "CELL_SUITES=$SUITES"
  -v "$CORPUS:/corpus:ro" -v "$CELLENV:/cellenv:ro" -v "$OUT:/kafout"
  "$IMAGE" sh /corpus/kaf/cell_exec.sh)
printf '%q ' "${EARGS[@]}" > "$OUT/docker_argv_exec.txt"; echo >> "$OUT/docker_argv_exec.txt"
"${EARGS[@]}" > "$OUT/exec.log" 2>&1
EXEC_RC=$?
echo "$EXEC_RC" > "$OUT/exec.rc"
log "exec rc=$EXEC_RC"
exit "$EXEC_RC"
