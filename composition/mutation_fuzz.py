#!/usr/bin/env python3
"""Digest-mutation security fuzzer for the JCS conformance corpus.

For every vector set that has a runner_python.py, tamper ONE expected hash/ref
value in the fixture and re-run the runner. A conformant runner MUST reject the
tampered fixture (non-zero exit). An 'ESCAPE' means the runner accepted forged
evidence -> a trivial-pass security hole.

Runs offline. Skips sets whose signature deps are not importable here.
Exit 0 iff zero escapes.
"""
from __future__ import annotations
import json, subprocess, sys, shutil, tempfile, re, importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
VEC = ROOT / "vectors"
HEXRE = re.compile(r'^(sha256:)?[0-9a-f]{64}$')
B64RE = re.compile(r'^[A-Za-z0-9+/]{40,}={0,2}$')

# mirror verify_corpus SIGNATURE_DEPS (OR-alternatives supported)
SIGDEPS = {
    "epi_pqc_v0": [("pqcrypto",)],
    "multichain_ed25519_substrate_v0": [("nacl",)],
    "rfc9421_proxy_chain_v0": [("algovoi_rfc9421_verifier",)],
    "rfc9421_proxy_chain_v1": [("nacl",)],
    "execution_ref_v1": [("algovoi_substrate.execution_ref", "algovoi_execution_ref")],
}

def importable(name):
    try: return importlib.util.find_spec(name) is not None
    except ModuleNotFoundError: return False

def deps_missing(setname):
    for alts in SIGDEPS.get(setname, []):
        if not any(importable(a) for a in alts):
            return True
    return False

def walk(obj, path=()):
    if isinstance(obj, dict):
        for k, v in obj.items(): yield from walk(v, path + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj): yield from walk(v, path + (i,))
    elif isinstance(obj, str):
        yield path, obj

def setp(obj, path, val):
    o = obj
    for p in path[:-1]: o = o[p]
    o[path[-1]] = val

def flip(s):
    if HEXRE.match(s):
        i = s.rfind(':') + 1
        return s[:i] + ('1' if s[i] != '1' else '0') + s[i+1:]
    if B64RE.match(s):
        c = 'A' if s[0] != 'A' else 'B'
        return c + s[1:]
    return None

# Forge the CLAIMED value: target keys named 'expected_*' (the value a runner
# recomputes and compares). This is the precise tamper test -- a load-bearing
# runner MUST reject a forged expected value. We deliberately do NOT target
# top-level context/duplicate fields (those aren't recomputed, so mutating them
# is not a security signal -- it produced false positives in a broader sweep).
NEG_HINT = ("negatives", "must", "reject", "claimed", "tamper")

def pick_target(obj):
    cands = []
    for path, val in walk(obj):
        if flip(val) is None: continue
        key = str(path[-1]) if path else ""
        joined = "/".join(str(p) for p in path).lower()
        if any(h in joined for h in NEG_HINT):
            continue  # skip negative/claimed elements (already-expected-to-differ)
        if "expected" not in key.lower():
            continue  # only forge claimed 'expected_*' outputs
        cands.append((path, val))
    return (cands[0][0], cands[0][1]) if cands else None

def fixture_of(setdir):
    pref = setdir / f"{setdir.name}.json"
    if pref.exists(): return pref
    js = [p for p in setdir.glob("*.json") if p.name not in ("package.json","package-lock.json")]
    return js[0] if js else None

# Base dependencies every substrate runner needs. Their absence is NOT a
# per-set signature-dep skip: it makes almost every baseline fail, which
# previously drained the run to zero real tests while still printing green.
# Treat a missing base dep as a hard error so the fuzzer never claims
# "all runners reject forged evidence" from an environment that could not run
# a single runner.
BASE_DEPS = ("algovoi_substrate", "rfc8785")

def run(setdir, fixture):
    r = subprocess.run([sys.executable, "runner_python.py", fixture.name],
                       cwd=setdir, capture_output=True, text=True, timeout=120)
    return r.returncode

def main():
    missing_base = [d for d in BASE_DEPS if not importable(d)]
    if missing_base:
        print(f"MUTATION FUZZ: cannot run, missing base deps: {' '.join(missing_base)}",
              file=sys.stderr)
        print("  (install the corpus requirements; a negative-test suite must not "
              "report green from an environment it cannot execute in)", file=sys.stderr)
        return 2

    escapes, caught, baseline_fails, tested, skipped = [], 0, [], 0, []
    for setdir in sorted(p for p in VEC.iterdir() if p.is_dir()):
        if not (setdir / "runner_python.py").exists():
            continue
        if deps_missing(setdir.name):
            skipped.append(f"{setdir.name}(deps)"); continue
        fx = fixture_of(setdir)
        if not fx: skipped.append(f"{setdir.name}(nofixture)"); continue
        try: obj = json.loads(fx.read_text(encoding="utf-8"))
        except Exception as e: skipped.append(f"{setdir.name}(parse:{e})"); continue
        tgt = pick_target(obj)
        if not tgt: skipped.append(f"{setdir.name}(notarget)"); continue
        path, orig = tgt
        # baseline must pass
        base_rc = run(setdir, fx)
        # tamper in a temp copy of the set dir
        with tempfile.TemporaryDirectory() as td:
            dst = Path(td) / setdir.name
            shutil.copytree(setdir, dst)
            mobj = json.loads(fx.read_text(encoding="utf-8"))
            setp(mobj, path, flip(orig))
            (dst / fx.name).write_text(json.dumps(mobj, indent=2) + "\n", encoding="utf-8", newline="\n")
            tam_rc = run(dst, dst / fx.name)
        if base_rc != 0:
            status = f"BASELINE-FAIL(rc={base_rc})"
            baseline_fails.append(setdir.name)
        elif tam_rc != 0:
            status = "CAUGHT"; caught += 1
        else:
            status = "ESCAPE"; escapes.append(setdir.name)
        tested += 1
        print(f"  {status:16s} {setdir.name:36s} target={'/'.join(str(p) for p in path)[:48]}")
    print(f"\nMUTATION FUZZ: tested={tested}  caught={caught}  escapes={len(escapes)}"
          f"  baseline_fails={len(baseline_fails)}  skipped={len(skipped)}")
    if skipped: print("  skipped:", " ".join(skipped))
    # Positive-work floor: green requires that mutations were actually caught,
    # no runner accepted a forgery, and no baseline failed. Any of these being
    # off means the suite did not prove what its banner claims.
    if escapes:
        print("  !!! ESCAPES (accepted forged evidence):", " ".join(escapes))
        return 1
    if baseline_fails:
        print("  !!! BASELINE FAILURES (runner could not pass its own fixture):",
              " ".join(baseline_fails))
        return 1
    if caught == 0:
        print("  !!! NO MUTATIONS EXERCISED (nothing was actually tested)")
        return 1
    print(f"  ALL {caught} TAMPERS REJECTED, 0 escapes, 0 baseline failures (load-bearing).")
    return 0

if __name__ == "__main__":
    sys.exit(main())
