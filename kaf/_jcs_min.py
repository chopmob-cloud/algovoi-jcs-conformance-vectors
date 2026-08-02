"""A minimal, dependency-free RFC 8785 (JCS) canonicalizer.

This is a genuinely independent second implementation, written from the RFC
8785 / ECMA-262 text and sharing NO code with rfc8785 or algovoi-substrate.
The Keystone Seal uses it as a real differential cross-check: seal.py and
kaf_verify.py canonicalize each receipt with BOTH this and rfc8785 and require
byte-for-byte agreement, so a bug in either implementation is caught rather
than hidden (the previous "cross-check" delegated to the same library twice).

Scope: the JSON value types a KAF receipt uses, which is all of JSON except
floating-point numbers. Receipts carry only strings, integers, booleans,
null, arrays, and objects. A float raises, by design: the seal domain has no
floats, and correct ECMAScript float formatting is exactly the subtle part we
do not want a hand implementation to get subtly wrong. Integers are bounded to
+-2^53 (the JCS/ECMAScript exact-integer range); anything larger raises.
"""
from __future__ import annotations

# ECMA-262 minimal string escaping (RFC 8785 section 3.2.2.2): only these are
# escaped; every other code point, including all non-ASCII, is emitted literally
# as UTF-8. Control characters below 0x20 with no short form use \u00xx.
_SHORT = {
    0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r",
    0x22: '\\"', 0x5C: "\\\\",
}

# ECMAScript Number.MAX_SAFE_INTEGER is 2**53 - 1; JCS rejects integers whose
# magnitude reaches 2**53 (they cannot be represented exactly as doubles).
_MAX_SAFE_INT = 2 ** 53 - 1


def _string(s: str) -> str:
    out = ["\""]
    for ch in s:
        cp = ord(ch)
        short = _SHORT.get(cp)
        if short is not None:
            out.append(short)
        elif cp < 0x20:
            out.append("\\u%04x" % cp)
        else:
            out.append(ch)
    out.append("\"")
    return "".join(out)


def _canon(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, bool):  # unreachable (handled above) but explicit
        return "true" if value else "false"
    if isinstance(value, int):
        if not (-_MAX_SAFE_INT <= value <= _MAX_SAFE_INT):
            raise ValueError(f"integer out of JCS exact range: {value}")
        return str(value)
    if isinstance(value, float):
        raise ValueError("floats are out of scope for the KAF seal canonicalizer")
    if isinstance(value, list):
        return "[" + ",".join(_canon(v) for v in value) + "]"
    if isinstance(value, dict):
        # RFC 8785 section 3.2.3: sort object keys by UTF-16 code units.
        # Comparing UTF-16-BE encodings orders by code unit exactly.
        for k in value:
            if not isinstance(k, str):
                raise ValueError("object keys must be strings")
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_string(k) + ":" + _canon(v) for k, v in items) + "}"
    raise ValueError(f"unsupported type for JCS: {type(value).__name__}")


def dumps(value) -> bytes:
    """Return the JCS canonical UTF-8 bytes of value."""
    return _canon(value).encode("utf-8")
