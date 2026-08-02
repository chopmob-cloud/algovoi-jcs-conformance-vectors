#!/usr/bin/env bash
# KAF P1 orchestrator (VM2 host side). Pulls the active cell images, records
# their exact digests (cells.lock.json), runs every requested cell
# (provision online, execute offline), and aggregates one run_summary.json.
#
# Usage: orchestrate_p1.sh <run_id> [cell_id ...]
#   No cell ids = every status=active cell in kaf/cells.json.
# Env: KAF_WORK (default /opt/algovoi/kaf)
set -u
RUN_ID="${1:?usage: orchestrate_p1.sh <run_id> [cell ...]}"; shift || true
FILTER=("$@")

KAF_WORK="${KAF_WORK:-/opt/algovoi/kaf}"
CORPUS="$KAF_WORK/algovoi-jcs-conformance-vectors"
RUNDIR="$KAF_WORK/runs/$RUN_ID"
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

echo "== KAF run $RUN_ID: pulling images =="
: > "$RUNDIR/pull_digests.tsv"
while IFS='|' read -r cid image lang suites; do
  docker pull -q "$image" >/dev/null || { echo "pull failed: $image"; exit 3; }
  digest="$(docker image inspect --format '{{join .RepoDigests ","}}' "$image")"
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

python3 - "$RUNDIR" > "$RUNDIR/run_summary.json" <<'EOF'
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
    overall = None
    tsv = os.path.join(d, "suites.tsv")
    if os.path.exists(tsv):
        for line in open(tsv, encoding="utf-8"):
            name, _, rc = line.rstrip("\n").partition("\t")
            if name == "overall":
                overall = int(rc)
            else:
                suites[name] = int(rc)
    prov = None
    pj = os.path.join(d, "provision.json")
    if os.path.exists(pj):
        rec = json.load(open(pj, encoding="utf-8"))
        prov = {"failed_specs": rec.get("failed_specs", [])}
    canary = None
    cl = os.path.join(d, "canary.log")
    if os.path.exists(cl):
        canary = open(cl, encoding="utf-8").read().strip().splitlines()[:1]
        canary = canary[0] if canary else None
    if overall is None or overall != 0:
        ok = False
    cells[cid] = {"suites": suites, "overall": overall, "canary": canary,
                  "provision": prov}
print(json.dumps({"cells": cells, "all_green": ok}, indent=1, sort_keys=True))
EOF

echo "== KAF run $RUN_ID summary =="
python3 - "$RUNDIR/run_summary.json" <<'EOF'
import json, sys
s = json.load(open(sys.argv[1], encoding="utf-8"))
for cid, c in sorted(s["cells"].items()):
    suites = " ".join(f"{k}={v}" for k, v in sorted(c["suites"].items()))
    print(f"  {cid:16s} overall={c['overall']} {suites}")
print("ALL GREEN" if s["all_green"] else "FAILURES PRESENT")
EOF

[ -z "$FAILED" ] && exit 0 || { echo "failed cells:$FAILED"; exit 1; }
