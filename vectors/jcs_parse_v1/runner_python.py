#!/usr/bin/env python3
"""Reference runner for jcs_parse_v1.

Demonstrates the parse-layer gate: reject duplicate object members BEFORE
canonicalisation. The gate is a json.loads object_pairs_hook, which is the
only place the duplicate is still visible.

Usage:  python runner_python.py [jcs_parse_v1.json]
Exit 0 when every vector reaches its stated verdict.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path


class DuplicateMember(ValueError):
    """Raised when an object carries the same member name twice."""


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    """object_pairs_hook that enforces RFC 8259 section 4 per object."""
    seen: set[str] = set()
    for name, _ in pairs:
        if name in seen:
            raise DuplicateMember(name)
        seen.add(name)
    return dict(pairs)


def parse_strict(raw: bytes) -> object:
    """Parse JSON, rejecting duplicate object members. Raises DuplicateMember."""
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)


def main(path: str = "jcs_parse_v1.json") -> int:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    failures: list[str] = []

    for v in data["accept"]:
        raw = base64.b64decode(v["input_b64"])
        try:
            parse_strict(raw)
        except DuplicateMember as exc:
            failures.append(f"{v['id']}: expected accept, rejected duplicate {exc!s}")

    for v in data["reject"]:
        raw = base64.b64decode(v["input_b64"])
        try:
            parse_strict(raw)
        except DuplicateMember:
            continue
        failures.append(f"{v['id']}: expected {v['expected_code']}, but parsed cleanly")

    total = len(data["accept"]) + len(data["reject"])
    if failures:
        for f in failures:
            print(f"FAIL {f}")
        print(f"\n{len(failures)}/{total} vectors failed")
        return 1

    print(f"{total}/{total} vectors reached their stated verdict "
          f"({len(data['accept'])} accept, {len(data['reject'])} reject)")
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
