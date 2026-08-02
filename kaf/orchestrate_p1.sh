#!/usr/bin/env bash
# KAF P1 orchestrator (VM2 host side). Pulls the active cell images, records
# their exact digests (cells.lock.json), runs every requested cell
# (provision online, execute offline), and aggregates one run_summary.json.
#
# Usage: orchestrate_p1.sh <run_id> [cell_id ...]
#   No cell ids = every status=active cell in kaf/cells.json.
# Env: KAF_WORK (default /opt/algovoi/kaf); KAF_RESUME=1 to allow aggregating a
#      run directory that already holds results (default: refuse, so a rerun
#      never merges stale cell results with fresh ones).
set -u
RUN_ID="${1:?usage: orchestrate_p1.sh <run_id> [cell ...]}"; shift || true
FILTER=("$@")

KAF_WORK="${KAF_WORK:-/opt/algovoi/kaf}"
CORPUS="$KAF_WORK/algovoi-jcs-conformance-vectors"
RUNDIR="$KAF_WORK/runs/$RUN_ID"

# F3: a run_id must be fresh. Aggregation walks every dir under results/, so
# reusing a populated run_id would merge stale cell results (produced from a
# different corpus commit) with new ones and seal them under one commit.
if [ -d "$RUNDIR/results" ] && [ -n "$(ls -A "$RUNDIR/results" 2>/dev/null)" ]; then
  if [ "${KAF_RESUME:-0}" != "1" ]; then
    echo "run '$RUN_ID' already has results ($RUNDIR/results); refuse to merge stale into fresh." >&2
    echo "use a new run id, or KAF_RESUME=1 to override deliberately." >&2
    exit 2
  fi
  echo "KAF_RESUME=1: reusing existing $RUNDIR/results (operator override)" >&2
fi
mkdir -p "$RUNDIR/results" "$RUNDIR/cellenv"

STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
COMMIT="$(git -C "$CORPUS" rev-parse HEAD 2>/dev/null || echo unknown)"
BRANCH="$(git -C "$CORPUS" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"

# Select cells (id|image|lang|suites_csv), active only, optional id filter.
SELECT="$(FILTER="${FILTER[*]:-}" python3 - "$CORPUS/kaf/cells.json" <<'EOF'
import json, os, sys
cat = json.load(open(sys.argv[1], encoding="utf-8"))
flt = set(os.environ.get("FILTER", "").split())
for c in cat["cells"]:
    if c["status"] != "active":
        continue
    if flt and c["id"] not in flt:
        continue
    print("|".join([c["id"], c["image"], c["lang"], ",".join(c["suites"])]))
EOF
)"
[ -n "$SELECT" ] || { echo "no cells selected"; exit 2; }

# F4: a filter id that matched nothing (typo, or a pending-vendor cell) must be
# a loud error, not a silent omission that reads as coverage.
if [ "${#FILTER[@]}" -gt 0 ]; then
  SELECTED_IDS=" $(printf '%s\n' "$SELECT" | cut -d'|' -f1 | tr '\n' ' ')"
  UNMATCHED=""
  for want in "${FILTER[@]}"; do
    case "$SELECTED_IDS" in *" $want "*) : ;; *) UNMATCHED="$UNMATCHED $want" ;; esac
  done
  [ -z "$UNMATCHED" ] || { echo "unmatched cell id(s):$UNMATCHED (not active in cells.json)"; exit 2; }
fi

echo "== KAF run $RUN_ID: pulling images =="
: > "$RUNDIR/pull_digests.tsv"
while IFS='|' read -r cid image lang suites; do
  docker pull -q "$image" >/dev/null || { echo "pull failed: $image"; exit 3; }
  # F9: an unchecked inspect (image pruned between pull and inspect) would
  # record a blank digest and poison the pinned-digest provenance the receipt
  # depends on. Require a non-empty digest.
  digest="$(docker image inspect --format '{{join .RepoDigests ","}}' "$image")" \
    || { echo "inspect failed: $image"; exit 3; }
  [ -n "$digest" ] || { echo "empty digest for $image (no RepoDigests)"; exit 3; }
  printf '%s\t%s\t%s\n' "$cid" "$image" "$digest" >> "$RUNDIR/pull_digests.tsv"
  echo "  $cid $image -> $digest"
done <<< "$SELECT"

python3 - "$RUNDIR/pull_digests.tsv" > "$RUNDIR/cells.lock.json" <<'EOF'
import json, sys
rows = [l.rstrip("\n").split("\t") for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
print(json.dumps({"locked": [{"cell": r[0], "image": r[1], "digest": r[2]} for r in rows]},
                 indent=1, sort_keys=True))
EOF

echo "== KAF run $RUN_ID: executing cells =="
FAILED=""
while IFS='|' read -r cid image lang suites; do
  echo "-- cell $cid ($image, suites: $suites)"
  bash "$CORPUS/kaf/run_cell.sh" "$cid" "$image" "$lang" "$suites" "$RUNDIR" "$CORPUS" \
    || FAILED="$FAILED $cid"
done <<< "$SELECT"

FINISHED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
STARTED="$STARTED" FINISHED="$FINISHED" COMMIT="$COMMIT" BRANCH="$BRANCH" RUN_ID="$RUN_ID" \
python3 - "$RUNDIR" > "$RUNDIR/run_meta.json" <<'EOF'
import json, os, platform, sys
print(json.dumps({
    "run_id": os.environ["RUN_ID"],
    "host": platform.node(),
    "started": os.environ["STARTED"],
    "finished": os.environ["FINISHED"],
    "corpus_commit": os.environ["COMMIT"],
    "corpus_branch": os.environ["BRANCH"],
}, indent=1, sort_keys=True))
EOF

# F7: write the summary atomically and check the aggregator's exit code, so a
# torn suites.tsv line cannot leave an empty run_summary.json beside exit 0.
# F2/F10: all_green is false if ANY cell has a nonzero overall, a missing
# overall, a recorded provisioning failure (failed_specs), or a duplicate
# suite key. Provisioning is a recorded exception, not a free pass: a tolerated
# pip/gem failure becomes a coverage hole, so it degrades the run.
if ! python3 - "$RUNDIR" > "$RUNDIR/run_summary.json.tmp" <<'EOF'
import json, os, sys
rundir = sys.argv[1]
cells = {}
ok = True
resroot = os.path.join(rundir, "results")
for cid in sorted(os.listdir(resroot)):
    d = os.path.join(resroot, cid)
    if not os.path.isdir(d):
        continue
    suites = {}
    dup = False
    overall = None
    tsv = os.path.join(d, "suites.tsv")
    if os.path.exists(tsv):
        for line in open(tsv, encoding="utf-8"):
            line = line.rstrip("\n")
            if not line:
                continue
            name, _, rc = line.partition("\t")
            rc = int(rc)  # torn/non-integer rc raises -> aggregator fails loud
            if name == "overall":
                overall = rc
            else:
                if name in suites:
                    dup = True
                suites[name] = rc
    prov_failed = []
    pj = os.path.join(d, "provision.json")
    if os.path.exists(pj):
        rec = json.load(open(pj, encoding="utf-8"))
        prov_failed = [s for s in rec.get("failed_specs", []) if s]
    canary = None
    cl = os.path.join(d, "canary.log")
    if os.path.exists(cl):
        lines = open(cl, encoding="utf-8").read().strip().splitlines()
        canary = lines[0] if lines else None
    degraded = []
    if overall is None:
        degraded.append("no-overall")
    elif overall != 0:
        degraded.append("overall-nonzero")
    if prov_failed:
        degraded.append("provision-failed")
    if dup:
        degraded.append("duplicate-suite")
    if degraded:
        ok = False
    cells[cid] = {"suites": suites, "overall": overall, "canary": canary,
                  "provision_failed_specs": prov_failed, "degraded": degraded}
print(json.dumps({"cells": cells, "all_green": ok}, indent=1, sort_keys=True))
EOF
then
  echo "FATAL: run_summary aggregation failed (corrupt suites.tsv?)" >&2
  rm -f "$RUNDIR/run_summary.json.tmp"
  exit 4
fi
mv "$RUNDIR/run_summary.json.tmp" "$RUNDIR/run_summary.json"

echo "== KAF run $RUN_ID summary =="
python3 - "$RUNDIR/run_summary.json" <<'EOF'
import json, sys
s = json.load(open(sys.argv[1], encoding="utf-8"))
for cid, c in sorted(s["cells"].items()):
    suites = " ".join(f"{k}={v}" for k, v in sorted(c["suites"].items()))
    deg = (" DEGRADED:" + ",".join(c["degraded"])) if c.get("degraded") else ""
    print(f"  {cid:16s} overall={c['overall']} {suites}{deg}")
print("ALL GREEN" if s["all_green"] else "FAILURES PRESENT")
EOF

# Final verdict requires BOTH: no cell process failed, and the aggregated
# all_green is true (so a provisioning hole or duplicate-suite mask cannot pass).
ALLGREEN="$(python3 -c 'import json,sys; print("1" if json.load(open(sys.argv[1]))["all_green"] else "0")' "$RUNDIR/run_summary.json")"
if [ -z "$FAILED" ] && [ "$ALLGREEN" = "1" ]; then
  exit 0
fi
echo "failed cells:${FAILED:- none}; all_green=$ALLGREEN"
exit 1
