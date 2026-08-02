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
import re
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
# additionally need a library beyond algovoi-substrate: most verify a
# cryptographic signature; execution_ref_v1 needs the execution_ref helper.
# All are on PyPI; `pip install -r requirements.txt` enables full coverage.
# Map: set -> [(import_name, pip_name), ...]. import_name may be a tuple of
# alternatives; the requirement is met if ANY of them imports, matching a
# runner that falls back across module locations.
SIGNATURE_DEPS = {
    "epi_pqc_v0": [("pqcrypto", "pqcrypto")],
    "multichain_ed25519_substrate_v0": [("nacl", "PyNaCl")],
    "rfc9421_proxy_chain_v0": [("algovoi_rfc9421_verifier", "algovoi-rfc9421-verifier")],
    "rfc9421_proxy_chain_v1": [("nacl", "PyNaCl")],
    # runner tries algovoi_substrate.execution_ref (native in substrate 1.0.0+),
    # then the standalone algovoi-execution-ref package; either satisfies it.
    "execution_ref_v1": [
        (("algovoi_substrate.execution_ref", "algovoi_execution_ref"),
         "algovoi-execution-ref"),
    ],
}


def _importable(name: str) -> bool:
    """True if `name` can be located as a module/submodule here."""
    try:
        return importlib.util.find_spec(name) is not None
    except ModuleNotFoundError:
        # A submodule whose parent exists but which is itself absent.
        return False


def _missing_deps(set_name: str) -> list[str]:
    """pip names of any required library not importable here. An import_name
    may be a tuple of alternatives; the requirement is met if ANY imports."""
    missing = []
    for import_name, pip_name in SIGNATURE_DEPS.get(set_name, []):
        alts = (import_name,) if isinstance(import_name, str) else tuple(import_name)
        if not any(_importable(a) for a in alts):
            missing.append(pip_name)
    return missing


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


# Auxiliary JSONs that are not standalone fixtures a runner verifies on its own
# (schemas, manifests, expected-output side files, npm/ts config, payload
# fragments). Everything else in a set dir is treated as a REAL fixture that
# must verify.
_AUX_JSON = re.compile(r'schema|manifest|expected|package|tsconfig|payload', re.I)


def _real_fixtures(set_dir: Path) -> list[str]:
    return [c for c in _vector_jsons(set_dir) if not _AUX_JSON.search(Path(c).name)]


def _run_set(set_dir: Path) -> tuple[str, str]:
    """Return (status, detail). status in {PASS, FAIL, SCHEMA}.

    Every REAL fixture the set ships must verify. Running each real fixture
    through the runner means a runner that consumes argv[1] is tested against
    all of its fixtures (no passing sibling can mask a failing one), while a
    runner that ignores argv simply reads its own file for each and returns the
    same verdict. A no-arg invocation is the fallback only when the set ships no
    resolvable fixture (runner defaults its own path)."""
    runner = _runner(set_dir)
    if runner is None:
        return "SCHEMA", "no runner (schema/doc-only set)"

    def _run(argv):
        try:
            r = subprocess.run(
                [sys.executable, runner, *argv],
                cwd=set_dir, capture_output=True, text=True, timeout=120,
            )
        except subprocess.TimeoutExpired:
            return None, "timeout"
        tail = (r.stdout.strip().splitlines() or ["ok"])[-1].strip()
        return r.returncode, tail

    fixtures = _real_fixtures(set_dir)
    if fixtures:
        results = [(Path(c).name, *_run([c])) for c in fixtures]
        failed = [(n, rc, d) for (n, rc, d) in results if rc != 0]
        passed = [(n, rc, d) for (n, rc, d) in results if rc == 0]
        if failed and passed:
            # Some real fixtures verified and some did not: a genuine
            # divergence that a first-pass short-circuit used to hide.
            return "FAIL", f"{failed[0][0]} rc={failed[0][1]} (sibling(s) passed)"
        if failed and not passed:
            # None passed with an explicit fixture: the runner may take no
            # argv and default its own path -> try that before declaring FAIL.
            rc, detail = _run([])
            if rc == 0:
                return "PASS", detail
            return "FAIL", f"{failed[0][0]} rc={failed[0][1]}"
        return "PASS", f"{len(passed)} fixture(s): {passed[-1][2]}"

    rc, detail = _run([])
    if rc == 0:
        return "PASS", detail
    return "FAIL", detail if rc is None else f"rc={rc}"


# Pinned coverage floor: the corpus ships this many vector-set directories.
# A smaller count means a partial checkout or a silently dropped set, which
# must turn the run red rather than shrink the denominator behind a green
# verdict. Raise this when sets are added.
EXPECTED_MIN_SETS = 49

# Sets legitimately shipping no runner (pure schema/doc). Currently none: every
# set carries a runner, so ANY set resolving to SCHEMA is a renamed/deleted
# runner and must fail the run, not vanish into a "schema-only" count.
SCHEMA_ALLOW: set[str] = set()


def main() -> int:
    set_dirs = sorted(p for p in VECTORS.iterdir() if p.is_dir())
    width = 74
    print("=" * width)
    print("AlgoVoi conformance corpus -- Verify It Yourself")
    print("offline; SHA-256 + JCS (RFC 8785) over published inputs only")
    print("=" * width)

    if len(set_dirs) < EXPECTED_MIN_SETS:
        print(f"FATAL: found {len(set_dirs)} vector sets, expected at least "
              f"{EXPECTED_MIN_SETS}. Partial checkout or a dropped set; refusing "
              f"to report a verdict over an incomplete corpus.")
        return 2

    npass = nfail = nschema = nexternal = ndeps = 0
    failed = []
    unexpected_schema = []
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
            if d.name not in SCHEMA_ALLOW:
                # A set with no runner that is not on the allow-list is a
                # renamed/deleted runner, not a doc-only set: fail it.
                unexpected_schema.append(d.name)
        else:
            nfail += 1
            failed.append(d.name)
        mark = {"PASS": "PASS  ", "FAIL": "FAIL  ", "SCHEMA": "SCHEMA"}[status]
        print(f"{mark} {d.name:38s} {detail[:30]}")

    print("-" * width)
    # Composition proofs. Each runs its own recompute + chained-equality check
    # and fails closed on any broken link. Run with a timeout so one hanging
    # proof cannot stall the whole verifier, and count a timeout/crash as FAIL.
    COMPOSITIONS = [
        ("regulated_lifecycle_v1/verify_lifecycle.py", "regulated_lifecycle_v1 (composition keystone)", "5/5 links byte-for-byte"),
        ("regulatory_audit_trail_v1/verify_audit_trail.py", "regulatory_audit_trail_v1 (audit trail composition)", "6/6 stages byte-for-byte"),
        ("spend_decision_chain_v1/verify_chain.py", "spend_decision_chain_v1 (decision chain composition)", "8/8 links byte-for-byte"),
        ("keystone_v1/verify_keystone.py", "keystone_v1 (full keystone flow incl execution tier)", "6/6 links byte-for-byte"),
        ("settlement_binding_v1/verify_settlement_binding.py", "settlement_binding_v1 (settlement tier binds to keystone execution)", "6/6 links byte-for-byte"),
        ("pef_keystone_v1/verify_pef_keystone.py", "pef_keystone_v1 (PEF signed-transport wraps + pins a keystone fact)", "6/6 links byte-for-byte"),
        ("refund_execution_v1/verify_refund_execution.py", "refund_execution_v1 (refund binds to keystone execution)", "5/5 links byte-for-byte"),
        ("audit_chain_of_frames_v1/verify_audit_chain_of_frames.py", "audit_chain_of_frames_v1 (lifecycle as chained PEF frames, capped)", "6/6 links byte-for-byte"),
        ("compliance_gate_keystone_v1/verify_compliance_gate_keystone.py", "compliance_gate_keystone_v1 (compliance verdict binds the decision)", "5/5 links byte-for-byte"),
        ("cancellation_keystone_v1/verify_cancellation_keystone.py", "cancellation_keystone_v1 (cancellation closes the keystone authority)", "4/4 links byte-for-byte"),
        ("guard_keystone_v1/verify_guard_keystone.py", "guard_keystone_v1 (keystone admitted under the input-bounds profile)", "3/3 within bounds"),
    ]
    comp_ok = True
    for rel, label, count_text in COMPOSITIONS:
        try:
            r = subprocess.run(
                [sys.executable, str(HERE / rel)],
                capture_output=True, text=True, timeout=120,
            )
            ok = r.returncode == 0
        except subprocess.TimeoutExpired:
            ok = False
            count_text = "TIMEOUT"
        comp_ok = comp_ok and ok
        print(f"{'PASS  ' if ok else 'FAIL  '} {label}   {count_text if ok else 'BROKEN'}")

    print("=" * width)
    print(f"sets: PASS={npass}  FAIL={nfail}  schema-only={nschema}   "
          f"needs-deps={ndeps}   external={nexternal}   "
          f"composition={'PASS' if comp_ok else 'FAIL'}")
    if failed:
        print("FAILED:", " ".join(failed))
    if unexpected_schema:
        print("UNEXPECTED SCHEMA-ONLY (runner missing/renamed, not doc-only):",
              " ".join(unexpected_schema))
    ok = (nfail == 0 and comp_ok and not unexpected_schema)
    if ok:
        print(f"\nALL {npass} RUN SETS + COMPOSITION KEYSTONE REPRODUCE BYTE-FOR-BYTE.")
        print("Your implementation is conformant with the AlgoVoi L1 substrate.")
    if deps_skipped:
        print(f"\n{ndeps} set(s) skipped (need an extra library): "
              f"{' '.join(deps_skipped)}")
        print("For full coverage:  pip install -r requirements.txt")
    print("(external = verified against a third-party service, outside this corpus.)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
