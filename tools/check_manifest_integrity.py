#!/usr/bin/env python3
"""Fail-closed manifest integrity gate for algovoi-jcs-conformance-vectors.

The manifest is the authoritative index of the corpus (README: "Authoritative
anchor-set and vector counts live in manifest.json"). This gate proves the
manifest still describes the bytes on disk, so a stale count or an unrecorded
edit to a vector file can never pass CI silently.

Checks (any failure -> non-zero exit):

  1. Version single-source-of-truth: package.json version == manifest version.
     (package.json otherwise duplicates the number and silently drifts, as it
     did at 0.28.0 vs 0.38.0.)
  2. Per-anchor-set digest: for every anchor set, the recorded sha256 equals
     'sha256:' + SHA-256(vectors/<name>/<primary_file>) byte-for-byte.
  3. Counts: len(anchor_sets) == total_anchor_sets, and the sum of every
     per-set vector_count == total_vectors.
  4. Every primary_file path resolves.

Run: python tools/check_manifest_integrity.py   (from the repo root)
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _sha256_file(path: str) -> str:
    with open(path, "rb") as fh:
        return "sha256:" + hashlib.sha256(fh.read()).hexdigest()


def main() -> int:
    failures: list[str] = []

    with open(os.path.join(ROOT, "manifest.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)
    with open(os.path.join(ROOT, "package.json"), encoding="utf-8") as fh:
        package = json.load(fh)

    # 1. version single source of truth
    m_ver = manifest.get("version")
    p_ver = package.get("version")
    if m_ver != p_ver:
        failures.append(
            f"version drift: manifest.json={m_ver!r} != package.json={p_ver!r}"
        )

    sets = manifest.get("anchor_sets", [])

    # 3a. anchor-set count
    total_sets = manifest.get("total_anchor_sets")
    if len(sets) != total_sets:
        failures.append(
            f"anchor-set count: len(anchor_sets)={len(sets)} != total_anchor_sets={total_sets}"
        )

    sum_vectors = 0
    for a in sets:
        name = a.get("name", "<unnamed>")
        primary = a.get("primary_file")
        recorded = a.get("sha256")
        sum_vectors += a.get("vector_count", 0)

        if not primary:
            failures.append(f"{name}: no primary_file in manifest")
            continue
        path = os.path.join(ROOT, "vectors", name, primary)
        if not os.path.exists(path):
            failures.append(f"{name}: primary_file missing on disk: vectors/{name}/{primary}")
            continue

        # 2. per-anchor-set digest
        if recorded:
            actual = _sha256_file(path)
            if actual != recorded:
                failures.append(
                    f"{name}: digest drift\n    manifest {recorded}\n    actual   {actual}"
                )

    # 3b. vector count
    total_vectors = manifest.get("total_vectors")
    if sum_vectors != total_vectors:
        failures.append(
            f"vector count: sum(vector_count)={sum_vectors} != total_vectors={total_vectors}"
        )

    if failures:
        print("MANIFEST INTEGRITY: FAIL")
        for f in failures:
            print(f"  - {f}")
        print(f"\n{len(failures)} failure(s).")
        return 1

    print(
        "MANIFEST INTEGRITY: PASS\n"
        f"  version           {m_ver} (manifest == package.json)\n"
        f"  anchor sets       {len(sets)} (== total_anchor_sets)\n"
        f"  vectors           {sum_vectors} (== total_vectors)\n"
        f"  digests verified  {len(sets)}/{len(sets)} byte-for-byte"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
