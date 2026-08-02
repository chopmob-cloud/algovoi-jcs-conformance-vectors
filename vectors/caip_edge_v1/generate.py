#!/usr/bin/env python3
# Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0. See LICENSE beside this file.
"""
Generate caip_edge_v1.json: an adversarial CAIP-2/10/19 identifier accept/reject set.

This set is negative-testing-first. A chain-agnostic identifier that is folded into a
canonicalised, content-addressed record becomes part of the preimage, so a validator that
accepts a non-canonical identifier lets two verifiers diverge on the same logical record.
The vectors here are the malformed, whitespace, Unicode-confusable, delimiter and
cross-level inputs a conformant validator MUST reject, plus a spine of accept controls that
guard against over-rejection.

Each input is stored as ``input_b64`` (base64 of the exact UTF-8 bytes) so control and
non-ASCII characters survive any editor or code page; ``input_display`` is a Python repr
for humans. ``family`` groups the adversarial classes.

Two anchor traps are pinned because they are language-dependent and are where "both do
CAIP" validators diverge:
  * Python: ``$`` (no MULTILINE) matches just before a trailing ``\\n``, so ``^...$`` wrongly
    accepts ``eip155:1\\n``. Correct Python anchors are ``\\A`` and ``\\Z``. Each vector carries
    ``naive_py_caret_dollar`` = the verdict a naive Python ``^...$`` gives, computed here.
  * JavaScript: ``$`` WITH the ``m`` flag matches before any line terminator
    (``\\n \\r \\u2028 \\u2029``), so an ``m``-flagged ``^...$`` wrongly accepts those. Correct JS
    uses ``^...$`` without ``m``. runner_node_naive.mjs demonstrates that trap.

Usage:  python generate.py
"""
from __future__ import annotations
import base64
import json
import re
from pathlib import Path

OUT = Path(__file__).parent / "caip_edge_v1.json"

_CHAIN = r"[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}"
# correct reference (byte-canonical): \A .. \Z
_OK = {
    "caip2": re.compile(rf"\A{_CHAIN}\Z"),
    "caip10": re.compile(rf"\A{_CHAIN}:[-.%a-zA-Z0-9]{{1,128}}\Z"),
    "caip19": re.compile(rf"\A{_CHAIN}/[-a-z0-9]{{3,8}}:[-.%a-zA-Z0-9]{{1,128}}(/[-.%a-zA-Z0-9]{{1,78}})?\Z"),
}
# naive Python reference (the trap): ^ .. $
_NAIVE = {
    "caip2": re.compile(rf"^{_CHAIN}$"),
    "caip10": re.compile(rf"^{_CHAIN}:[-.%a-zA-Z0-9]{{1,128}}$"),
    "caip19": re.compile(rf"^{_CHAIN}/[-a-z0-9]{{3,8}}:[-.%a-zA-Z0-9]{{1,128}}(/[-.%a-zA-Z0-9]{{1,78}})?$"),
}

VEC: list[dict] = []
_seen_ids: set[str] = set()
_counter = 0


def add(kind: str, s: str, expectation: str, family: str, description: str) -> None:
    global _counter
    _counter += 1
    vid = f"caip-edge-{_counter:03d}-{family}"
    # de-duplicate the auto id if a family repeats
    while vid in _seen_ids:
        vid += "x"
    _seen_ids.add(vid)
    VEC.append({
        "vector_id": vid,
        "kind": kind,
        "family": family,
        "description": description,
        "input_b64": base64.b64encode(s.encode("utf-8")).decode("ascii"),
        "input_display": repr(s),
        "expectation": expectation,
        "naive_py_caret_dollar": "accept" if _NAIVE[kind].match(s) else "reject",
    })


A32 = "a" * 32
A128 = "a" * 128
T78 = "t" * 78

# ---------------------------------------------------------------- accept controls
add("caip2", "eip155:1", "accept", "control", "canonical CAIP-2 (spec example)")
add("caip2", "starknet:SN_GOERLI", "accept", "control", "reference allows uppercase and underscore")
add("caip2", "cosmos:Binance-Chain-Tigris", "accept", "control", "mixed case + hyphens in reference")
add("caip2", "12345:1", "accept", "control", "all-digit namespace is valid")
add("caip2", "a-b:1", "accept", "control", "hyphen allowed in namespace")
add("caip2", "abc:a", "accept", "control", "min namespace 3, min reference 1")
add("caip2", "abcdefgh:a", "accept", "control", "namespace at max length 8")
add("caip2", "abc:" + A32, "accept", "control", "reference at max length 32")
add("caip10", "eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb", "accept", "control", "canonical CAIP-10 (spec example)")
add("caip10", "hedera:mainnet:0.0.1234567890-zbhlt", "accept", "control", "address permits dot and dash")
add("caip10", "eip155:1:ab%20cd", "accept", "control", "address permits percent (URL-encoding)")
add("caip10", "abc:1:" + A128, "accept", "control", "address at max length 128")
add("caip19", "eip155:1/slip44:60", "accept", "control", "canonical CAIP-19 asset type (spec example)")
add("caip19", "eip155:1/erc721:0x06012c8cf97BEaD5deAe237070F9587f8E7A266d/771769", "accept", "control", "asset id with token_id")
add("caip19", "eip155:1/erc20:ab%2ecd", "accept", "control", "asset reference permits percent")
add("caip19", "abc:1/def:60/" + T78, "accept", "control", "token_id at max length 78")

# ---------------------------------------------------------------- length boundaries (reject the +1)
add("caip2", "ab:1", "reject", "len_ns", "namespace length 2 below min 3")
add("caip2", "abcdefghi:1", "reject", "len_ns", "namespace length 9 above max 8")
add("caip2", "eip155:", "reject", "len_ref", "reference length 0")
add("caip2", "eip155:" + "a" * 33, "reject", "len_ref", "reference length 33 above max 32")
add("caip10", "eip155:1:", "reject", "len_addr", "address length 0")
add("caip10", "eip155:1:" + "a" * 129, "reject", "len_addr", "address length 129 above max 128")
add("caip19", "eip155:1/ab:60", "reject", "len_asset_ns", "asset namespace length 2 below min 3")
add("caip19", "eip155:1/abcdefghi:60", "reject", "len_asset_ns", "asset namespace length 9 above max 8")
add("caip19", "eip155:1/slip44:", "reject", "len_asset_ref", "asset reference length 0")
add("caip19", "eip155:1/slip44:" + "a" * 129, "reject", "len_asset_ref", "asset reference length 129 above max 128")
add("caip19", "eip155:1/slip44:60/", "reject", "len_token", "token_id length 0 (trailing slash)")
add("caip19", "eip155:1/slip44:60/" + "t" * 79, "reject", "len_token", "token_id length 79 above max 78")

# ---------------------------------------------------------------- namespace charset (reject)
for bad, why in [("EIP155:1", "uppercase in namespace"), ("eip_155:1", "underscore in namespace"),
                 ("eip.155:1", "dot in namespace"), ("eip%155:1", "percent in namespace"),
                 ("eip 155:1", "space in namespace"), ("ei@55:1", "at-sign in namespace"),
                 ("eip/155:1", "slash in namespace")]:
    add("caip2", bad, "reject", "charset_ns", why)

# ---------------------------------------------------------------- reference charset (reject; ref has no . % / space @ :)
for bad, why in [("eip155:1.2", "dot not in reference charset"), ("eip155:1%2", "percent not in reference charset"),
                 ("eip155:na@me", "at-sign in reference"), ("eip155:a b", "space in reference"),
                 ("eip155:a\tb", "tab in reference")]:
    add("caip2", bad, "reject", "charset_ref", why)

# ---------------------------------------------------------------- address charset (caip10; addr has no _ : / space @)
for bad, why in [("eip155:1:0x_ab", "underscore not in address charset"), ("eip155:1:0x ab", "space in address"),
                 ("eip155:1:a@b", "at-sign in address"), ("eip155:1:a/b", "slash in address"),
                 ("eip155:1:a:b", "extra colon in address")]:
    add("caip10", bad, "reject", "charset_addr", why)

# ---------------------------------------------------------------- structural / delimiters (reject)
add("caip2", "eip155", "reject", "struct", "no colon separator")
add("caip2", ":1", "reject", "struct", "leading colon, empty namespace")
add("caip2", "eip155::1", "reject", "struct", "double colon, reference starts with colon")
add("caip2", "eip155:1:2", "reject", "struct", "extra segment (this is a CAIP-10 shape)")
add("caip19", "eip155:1slip44:60", "reject", "struct", "missing slash before asset namespace")
add("caip19", "eip155:1//slip44:60", "reject", "struct", "double slash before asset")
add("caip19", "eip155:1/slip4460", "reject", "struct", "missing colon in asset")
add("caip19", "eip155:1/slip44:60/1/2", "reject", "struct", "extra segment after token_id")
add("caip19", "eip155:1/slip44:60/", "reject", "struct", "trailing slash, empty token")

# ---------------------------------------------------------------- trailing / leading / embedded control chars
_TRAIL = {"lf": "\n", "crlf": "\r\n", "cr": "\r", "tab": "\t", "vtab": "\x0b",
          "ff": "\x0c", "nul": "\x00", "sp": " "}
for name, ch in _TRAIL.items():
    add("caip2", "eip155:1" + ch, "reject", "trail_ctrl", f"trailing {name!r} must be rejected")
add("caip10", "eip155:1:0xabc\n", "reject", "trail_ctrl", "CAIP-10 trailing newline")
add("caip19", "eip155:1/slip44:60\n", "reject", "trail_ctrl", "CAIP-19 trailing newline")
for name, ch in {"lf": "\n", "sp": " ", "tab": "\t", "nul": "\x00"}.items():
    add("caip2", ch + "eip155:1", "reject", "lead_ctrl", f"leading {name!r} must be rejected")
add("caip2", "eip155\n:1", "reject", "embed_ctrl", "embedded newline in identifier")
add("caip2", "eip\x00155:1", "reject", "embed_ctrl", "embedded NUL in namespace")

# ---------------------------------------------------------------- Unicode whitespace / line terminators (reject)
_UWS = {"u2028_lineSep": " ", "u2029_paraSep": " ", "u00a0_nbsp": " ",
        "u3000_ideoSpace": "　", "u200b_zwsp": "​", "ufeff_bom": "﻿",
        "u0085_nel": "", "u2003_emSpace": " "}
for name, ch in _UWS.items():
    add("caip2", "eip155:1" + ch, "reject", "unicode_ws", f"trailing {name} must be rejected")
add("caip2", "﻿eip155:1", "reject", "unicode_ws", "leading BOM must be rejected")
add("caip2", "eip155​:1", "reject", "unicode_ws", "embedded zero-width space")

# ---------------------------------------------------------------- Unicode homoglyph / confusable / non-ASCII (reject)
add("caip2", "eip155:１", "reject", "unicode_confusable", "fullwidth digit U+FF11 is not ASCII 1")
add("caip2", "ｅip155:1", "reject", "unicode_confusable", "fullwidth e U+FF45 in namespace")
add("caip2", "еip155:1", "reject", "unicode_confusable", "Cyrillic e U+0435 homoglyph in namespace")
add("caip2", "eip155:1́", "reject", "unicode_confusable", "trailing combining acute U+0301")
add("caip2", "eip155:1\U0001f600", "reject", "unicode_confusable", "trailing emoji U+1F600")
add("caip2", "café:1", "reject", "unicode_confusable", "non-ASCII letter e-acute in namespace")
add("caip2", "eip155:²", "reject", "unicode_confusable", "superscript two U+00B2 is not a digit here")

# ---------------------------------------------------------------- cross-level confusion (reject at wrong level)
add("caip2", "eip155:1:0xabc", "reject", "xlevel", "a CAIP-10 is not a CAIP-2")
add("caip2", "eip155:1/slip44:60", "reject", "xlevel", "a CAIP-19 is not a CAIP-2")
add("caip10", "eip155:1", "reject", "xlevel", "a CAIP-2 is not a CAIP-10")
add("caip10", "eip155:1/slip44:60", "reject", "xlevel", "a CAIP-19 is not a CAIP-10")
add("caip19", "eip155:1", "reject", "xlevel", "a CAIP-2 is not a CAIP-19")
add("caip19", "eip155:1:0xabc", "reject", "xlevel", "a CAIP-10 is not a CAIP-19")

# ---------------------------------------------------------------- regex-metachar / injection flavored (reject)
for bad, why in [("eip155:1$", "trailing dollar metacharacter"), ("^eip155:1", "leading caret"),
                 ("eip155:.*", "dot-star, dot not in reference"), ("eip155:1|x", "pipe not in reference"),
                 ("..:1", "dot-dot namespace"), ("eip155:1\n<script>", "newline plus payload"),
                 ("eip155:1\x00extra", "NUL truncation with trailing bytes"),
                 ("eip155:1 OR 1=1", "sql-flavored payload with spaces")]:
    add("caip2", bad, "reject", "injection", why)

# empty
add("caip2", "", "reject", "empty", "empty string")


def _selfcheck() -> None:
    bad = []
    for v in VEC:
        s = base64.b64decode(v["input_b64"]).decode("utf-8")
        got = bool(_OK[v["kind"]].match(s))
        if got != (v["expectation"] == "accept"):
            bad.append(v["vector_id"])
    if bad:
        raise SystemExit(f"generator self-check FAILED (correct \\A..\\Z reference disagrees): {bad}")


def main() -> None:
    _selfcheck()
    n_acc = sum(1 for v in VEC if v["expectation"] == "accept")
    n_naive_div = sum(1 for v in VEC
                      if v["naive_py_caret_dollar"] != v["expectation"])
    doc = {
        "name": "caip_edge_v1",
        "license": "Apache-2.0",
        "copyright": "Copyright 2026 AlgoVoi (chopmob@gmail.com)",
        "spec": "CAIP-2 / CAIP-10 / CAIP-19 chain-agnostic identifier grammar",
        "spec_authorship": (
            "AlgoVoi-authored adversarial conformance set. Normative reference: "
            "ChainAgnostic/CAIPs CAIP-2, CAIP-10, CAIP-19. Negative-testing-first: it pins the "
            "malformed, whitespace, Unicode-confusable, delimiter and cross-level inputs a "
            "validator MUST reject, plus accept controls to guard against over-rejection, with "
            "the two language-dependent regex-anchor traps (Python trailing-newline; JavaScript "
            "m-flag line terminators) called out explicitly."
        ),
        "grammar": {
            "chain_id": "namespace ':' reference   namespace [-a-z0-9]{3,8}  reference [-_a-zA-Z0-9]{1,32}",
            "account_id": "chain_id ':' address     address [-.%a-zA-Z0-9]{1,128}",
            "asset_type": "chain_id '/' ns ':' ref   ns [-a-z0-9]{3,8}  ref [-.%a-zA-Z0-9]{1,128}",
            "asset_id": "asset_type '/' token_id     token_id [-.%a-zA-Z0-9]{1,78}",
        },
        "input_encoding": "input_b64 is base64 of the identifier's exact UTF-8 bytes; input_display is a Python repr for humans.",
        "counts": {
            "total": len(VEC),
            "accept": n_acc,
            "reject": len(VEC) - n_acc,
            "naive_py_caret_dollar_divergences": n_naive_div,
        },
        "vectors": VEC,
    }
    OUT.write_text(json.dumps(doc, indent=2, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n")
    fams = {}
    for v in VEC:
        fams[v["family"]] = fams.get(v["family"], 0) + 1
    print(f"wrote {OUT.name}: {len(VEC)} vectors ({n_acc} accept, {len(VEC) - n_acc} reject)")
    print(f"naive Python ^...$ divergences: {n_naive_div}")
    print("families: " + ", ".join(f"{k}={n}" for k, n in sorted(fams.items())))


if __name__ == "__main__":
    main()
