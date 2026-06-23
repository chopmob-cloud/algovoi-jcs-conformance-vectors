#!/usr/bin/env python3
"""
AlgoVoi conformance corpus -- single-command verifier ("Verify It Yourself").

Runs every published vector set in the corpus and the regulated-lifecycle
composition proof, then prints one conformance report. No network, no issuer
contact, no new vectors: just SHA-256 + JCS over the published inputs.

Purpose:
  - An L2 builder runs this once to self-certify their stack against the
    canonical bytes. If it passes, they are byte-compatible with the L1
    substrate and every party that uses it.
  - Any implementation on a non-canonical lineage (e.g. an RFC 3339 string
    timestamp instead of integer timestamp_ms) produces different bytes and
    fails the relevant sets here -- the divergence is testable, not asserted.

Apache-2.0. (c) AlgoVoi. Redistribution requires NOTICE attribution.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
VECTORS = ROOT / "vectors"

# Sets that are intentionally NOT part of the offline byte-for-byte corpus.
# We name them explicitly rather than silently skipping, so the claim "every
# set reproduces offline" stays honest.
EXTERNAL = {
    "service_trust_v0": "third-party (Crest/Supership); verified by POST to an "
    "external risk API, not offline SHA-256+JCS",
}

# The core corpus needs only algovoi-substrate (JCS + SHA-256). These sets
# additionally verify cryptographic signatures, so they need extra libraries.
# All are on PyPI; `pip install -r requirements.txt` enables full coverage.
# Map: set -> [(import_name, pip_name), ...].
SIGNATURE_DEPS = {
    "epi_pqc_v0": [("pqcrypto", "pqcrypto")],
    "multichain_ed25519_substrate_v0": [("nacl", "PyNaCl")],
    "rfc9421_proxy_chain_v0": [("algovoi_rfc9421_verifier", "algovoi-rfc9421-verifier")],
    "rfc9421_proxy_chain_v1": [("nacl", "PyNaCl")],
}


def _missing_deps(set_name: str) -> list[str]:
    """pip names of any required signature library not importable here."""
    return [
        pip_name
        for import_name, pip_name in SIGNATURE_DEPS.get(set_name, [])
        if importlib.util.find_spec(import_name) is None
    ]


def _runner(set_dir: Path) -> str | None:
    for name in ("runner_python.py", "verify.py"):
        if (set_dir / name).exists():
            return name
    return None


def _vector_jsons(set_dir: Path) -> list[str]:
    """Candidate vector files: the name-matching one first, then any other
    JSON that is not an npm manifest. Runner invocation differs across sets
    (some default the path, some require argv[1], some name the file with
    dashes), so we try each candidate until one verifies."""
    skip = {"package.json", "package-lock.json"}
    others = sorted(
        str(p) for p in set_dir.glob("*.json") if p.name not in skip
    )
    preferred = set_dir / f"{set_dir.name}.json"
    ordered: list[str] = []
    if preferred.exists():
        ordered.append(str(preferred))
    for o in others:
        if o not in ordered:
            ordered.append(o)
    return ordered


def _run_set(set_dir: Path) -> tuple[str, str]:
    """Return (status, detail). status in {PASS, FAIL, SCHEMA}."""
    runner = _runner(set_dir)
    if runner is None:
        return "SCHEMA", "no runner (schema/doc-only set)"
    # Try each candidate json as argv[1], then a no-arg invocation. The first
    # exit-0 run is authoritative (runners validate expected hashes, so a
    # wrong file cannot pass).
    attempts = [[c] for c in _vector_jsons(set_dir)] + [[]]
    last = None
    for argv in attempts:
        try:
            r = subprocess.run(
                [sys.executable, runner, *argv],
                cwd=set_dir, capture_output=True, text=True, timeout=120,
            )
        except subprocess.TimeoutExpired:
            return "FAIL", "timeout"
        if r.returncode == 0:
            tail = (r.stdout.strip().splitlines() or ["ok"])[-1].strip()
            return "PASS", tail
        last = r.returncode
    return "FAIL", f"rc={last}"


def main() -> int:
    set_dirs = sorted(p for p in VECTORS.iterdir() if p.is_dir())
    width = 74
    print("=" * width)
    print("AlgoVoi conformance corpus -- Verify It Yourself")
    print("offline; SHA-256 + JCS (RFC 8785) over published inputs only")
    print("=" * width)

    npass = nfail = nschema = nexternal = ndeps = 0
    failed = []
    deps_skipped = []
    for d in set_dirs:
        if d.name in EXTERNAL:
            nexternal += 1
            print(f"EXTERN {d.name:38s} {EXTERNAL[d.name][:30]}")
            continue
        missing = _missing_deps(d.name)
        if missing:
            ndeps += 1
            deps_skipped.append(d.name)
            print(f"DEPS   {d.name:38s} needs: pip install {' '.join(missing)}")
            continue
        status, detail = _run_set(d)
        if status == "PASS":
            npass += 1
        elif status == "SCHEMA":
            nschema += 1
        else:
            nfail += 1
            failed.append(d.name)
        mark = {"PASS": "PASS  ", "FAIL": "FAIL  ", "SCHEMA": "SCHEMA"}[status]
        print(f"{mark} {d.name:38s} {detail[:30]}")

    print("-" * width)
    # Composition keystone
    comp = subprocess.run(
        [sys.executable, str(HERE / "regulated_lifecycle_v1" / "verify_lifecycle.py")],
        capture_output=True, text=True,
    )
    comp_ok = comp.returncode == 0
    print(f"{'PASS  ' if comp_ok else 'FAIL  '} regulated_lifecycle_v1 (composition keystone)"
          f"   {'5/5 links byte-for-byte' if comp_ok else 'BROKEN'}")

    audit = subprocess.run(
        [sys.executable, str(HERE / "regulatory_audit_trail_v1" / "verify_audit_trail.py")],
        capture_output=True, text=True,
    )
    audit_ok = audit.returncode == 0
    print(f"{'PASS  ' if audit_ok else 'FAIL  '} regulatory_audit_trail_v1 (audit trail composition)"
          f"   {'6/6 stages byte-for-byte' if audit_ok else 'BROKEN'}")

    chain = subprocess.run(
        [sys.executable, str(HERE / "spend_decision_chain_v1" / "verify_chain.py")],
        capture_output=True, text=True,
    )
    chain_ok = chain.returncode == 0
    print(f"{'PASS  ' if chain_ok else 'FAIL  '} spend_decision_chain_v1 (decision chain composition)"
          f"   {'5/5 links byte-for-byte' if chain_ok else 'BROKEN'}")
    comp_ok = comp_ok and audit_ok and chain_ok

    print("=" * width)
    print(f"sets: PASS={npass}  FAIL={nfail}  schema-only={nschema}   "
          f"needs-deps={ndeps}   external={nexternal}   "
          f"composition={'PASS' if comp_ok else 'FAIL'}")
    if failed:
        print("FAILED:", " ".join(failed))
    if nfail == 0 and comp_ok:
        print(f"\nALL {npass} RUN SETS + COMPOSITION KEYSTONE REPRODUCE BYTE-FOR-BYTE.")
        print("Your implementation is conformant with the AlgoVoi L1 substrate.")
    if deps_skipped:
        print(f"\n{ndeps} signature set(s) skipped (need crypto libs): "
              f"{' '.join(deps_skipped)}")
        print("For full 24/24 coverage:  pip install -r requirements.txt")
    print("(external = verified against a third-party service, outside this corpus.)")
    return 0 if (nfail == 0 and comp_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
