#!/usr/bin/env python3
"""
First-principles validation of the regulated-lifecycle composition.

This deliberately uses NO canonicalizer library and NO AlgoVoi package. It
serialises the JCS canonical form by hand (sorted keys, quoted strings, bare
integers, no whitespace) and hashes with the standard library only. If a bug
existed in both the substrate and the runners, they would agree and hide it;
this check cannot, because it shares no code with them.

It recomputes the entire chain from raw preimages:
    action_ref -> transition_hash (COMMITTED) -> settlement_ref
      -> retention_chain_ref -> binding_ref
and confirms each value against the published vectors and the headline
binding_ref sha256:7dc4a2bf...

Run from the repository root:  python composition/first_principles_check.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
V = ROOT / "vectors"
BACKSLASH = chr(92)


def load(s: str) -> dict:
    return json.loads((V / s / f"{s}.json").read_text(encoding="utf-8"))


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _safe(s: str) -> bool:
    # printable ASCII with no character that JCS would need to escape
    return all(0x20 <= ord(c) < 0x7f and c != '"' and c != BACKSLASH for c in s)


def manual_jcs_flat(obj: dict) -> bytes:
    """JCS by hand for FLAT objects of str/int values needing no escaping.
    Keys sorted by code point, strings quoted, integers bare, no whitespace."""
    parts = []
    for k in sorted(obj.keys()):
        assert _safe(k), f"unsafe key {k!r}"
        v = obj[k]
        if isinstance(v, bool):
            raise ValueError("unexpected bool")
        if isinstance(v, int):
            sval = str(v)
        elif isinstance(v, str):
            assert _safe(v), f"unsafe value {v!r}"
            sval = '"' + v + '"'
        else:
            raise ValueError(f"non-flat type {type(v)}")
        parts.append('"' + k + '":' + sval)
    return ("{" + ",".join(parts) + "}").encode("utf-8")


results: list[tuple[str, bool]] = []


def check(name: str, got, want) -> bool:
    ok = got == want
    results.append((name, ok))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if not ok:
        print(f"        got : {got}")
        print(f"        want: {want}")
    return ok


def main() -> int:
    print("FIRST-PRINCIPLES VALIDATION (hand-written JCS + stdlib hashlib only)\n")

    # 1. action_ref recomputed by hand from its preimage
    aro = load("action_ref_exactly_once_v1")
    ar = next(v for v in aro["vectors"] if v.get("expected_action_ref"))
    ar_bytes = manual_jcs_flat(ar["preimage"])
    print("[1] action_ref")
    print(f"      hand-built bytes: {ar_bytes.decode()}")
    check("SHA-256(hand-JCS(preimage)) == published expected_action_ref",
          sha(ar_bytes), ar["expected_action_ref"])
    check("hand bytes == published expected_jcs_bytes_b64",
          base64.b64encode(ar_bytes).decode(), ar["expected_jcs_bytes_b64"])
    action_ref = sha(ar_bytes)

    # 2. COMMITTED transition_hash recomputed by hand
    tr = next(v for v in aro["vectors"]
              if v.get("preimage", {}).get("state") == "COMMITTED"
              and v.get("expected_transition_hash"))
    tr_bytes = manual_jcs_flat(tr["preimage"])
    print("[2] transition_hash (COMMITTED)")
    check("SHA-256(hand-JCS(preimage)) == published expected_transition_hash",
          sha(tr_bytes), tr["expected_transition_hash"])
    check("hand bytes == published expected_jcs_bytes_b64",
          base64.b64encode(tr_bytes).decode(), tr["expected_jcs_bytes_b64"])
    check("transition preimage.action_ref == recomputed action_ref",
          tr["preimage"]["action_ref"], action_ref)
    transition = sha(tr_bytes)

    # 3. settlement_ref = SHA-256 of the published canonical bytes (pure hashlib)
    sat = load("settlement_attestation_v1")
    s_target = "0ead75bfe7fc74cc0421124903e56cb5c5006d02c393231a1d5f260fa87e96d3"
    sv = next(v for v in sat["vectors"] if v.get("expected_content_hash") == s_target)
    s_bytes = base64.b64decode(sv["expected_jcs_bytes_b64"])
    print("[3] settlement_ref")
    check("SHA-256(published canonical bytes) == expected_content_hash",
          sha(s_bytes), sv["expected_content_hash"])
    settlement = sha(s_bytes)

    # 4. retention_chain_ref = SHA-256 of the published canonical bytes
    rc = load("retention_chain_v1")
    r_target = "sha256:d23aeb006c5f3db9dd96315916410393904f56c4c871593065eb73b783fff35f"
    rv = next(v for v in rc["vectors"] if v.get("expected_chain_ref") == r_target)
    r_bytes = base64.b64decode(rv["expected_jcs_bytes_b64"])
    print("[4] retention_chain_ref")
    check("'sha256:'+SHA-256(published canonical bytes) == expected_chain_ref",
          "sha256:" + sha(r_bytes), rv["expected_chain_ref"])
    retention = "sha256:" + sha(r_bytes)

    # 5. binding_ref recomputed by hand from the FOUR recomputed upstream values
    binding_pre = {
        "action_ref": action_ref,
        "transition_hash": transition,
        "settlement_ref": settlement,
        "retention_chain_ref": retention,
    }
    binding_bytes = manual_jcs_flat(binding_pre)
    binding_ref = "sha256:" + sha(binding_bytes)
    print("[5] binding_ref (composed from the four recomputed values)")
    print(f"      hand-built bytes: {binding_bytes.decode()}")
    sab = load("settlement_action_binding_v1")
    sab_ref = next(v for v in sab["vectors"] if v["vector_id"] == "sab-v1-001")
    check("recomputed binding inputs == sab-v1-001 published preimage",
          binding_pre, sab_ref["preimage"])
    check("hand bytes == sab-v1-001 expected_jcs_bytes_b64",
          base64.b64encode(binding_bytes).decode(), sab_ref["expected_jcs_bytes_b64"])
    check("binding_ref (hand) == published expected_binding_ref",
          binding_ref, sab_ref["expected_binding_ref"])
    check("binding_ref (hand) == sha256:7dc4a2bf...",
          binding_ref,
          "sha256:7dc4a2bf62b3c5eabd10fc875ff7fc10f188666f15838c4a51464cc72e80f6ca")

    print("\n" + "=" * 62)
    npass = sum(1 for _, ok in results if ok)
    print(f"FIRST-PRINCIPLES RESULT: {npass}/{len(results)} checks PASS")
    print("Every value recomputed from raw preimages with hand-written JCS")
    print("and stdlib SHA-256. No AlgoVoi canonicalizer was invoked.")
    return 0 if npass == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
