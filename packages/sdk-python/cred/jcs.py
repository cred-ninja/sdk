"""RFC 8785 JSON Canonicalization Scheme (JCS) serialization.

Matches the TypeScript reference (``canonicalJson`` in ``@credninja/attenuation``)
byte for byte: primitives as ECMAScript ``JSON.stringify`` writes them
(numbers in their shortest round-trip form, strings with the minimal
escapes), object members sorted by their UTF-16 code units, arrays in order.

Values with no JCS form raise :class:`CanonicalJsonError`: non-finite numbers,
integers outside the range a JavaScript number holds exactly
(``±(2**53 - 1)``), strings with a lone surrogate, non-string object keys,
and any type that is not ``None``, ``bool``, ``int``, ``float``, ``str``,
``list``/``tuple`` or ``dict``.
"""

from __future__ import annotations

import math
from decimal import Decimal
from typing import Any

__all__ = ["CanonicalJsonError", "canonical_json"]

_MAX_SAFE_INTEGER = 2**53 - 1

_SHORT_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


class CanonicalJsonError(ValueError):
    """A value has no RFC 8785 (JCS) serialization."""

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


def canonical_json(value: Any) -> str:
    """Serialize ``value`` per RFC 8785 (JCS)."""
    if value is None:
        return "null"
    # bool before int: bool is a subclass of int in Python.
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INTEGER:
            raise CanonicalJsonError(
                f"integer {value} is outside the range a JSON number holds exactly",
                "unsupported",
            )
        return str(int(value))
    if isinstance(value, float):
        return _serialize_number(value)
    if isinstance(value, str):
        return _serialize_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalJsonError(f"object key {key!r} is not a string", "unsupported")
        # UTF-16 code unit order, as Array.prototype.sort orders the keys.
        # Lone surrogates are rejected by _serialize_string before encoding.
        keys = sorted(value, key=_utf16_sort_key)
        return "{" + ",".join(f"{_serialize_string(k)}:{canonical_json(value[k])}" for k in keys) + "}"
    raise CanonicalJsonError(f"{type(value).__name__} has no JSON form", "unsupported")


def _utf16_sort_key(key: str) -> bytes:
    _check_surrogates(key)
    return key.encode("utf-16-be")


def _check_surrogates(value: str) -> None:
    # A Python str holds code points: an astral character is one code point,
    # so any surrogate code point here is unpaired.
    for char in value:
        if 0xD800 <= ord(char) <= 0xDFFF:
            raise CanonicalJsonError("string contains a lone surrogate", "unsupported")


def _serialize_string(value: str) -> str:
    _check_surrogates(value)
    out = ['"']
    for char in value:
        escaped = _SHORT_ESCAPES.get(char)
        if escaped is not None:
            out.append(escaped)
        elif ord(char) < 0x20:
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _serialize_number(value: float) -> str:
    """ECMAScript Number::toString(value) for a finite double."""
    if not math.isfinite(value):
        raise CanonicalJsonError(f"non-finite number {value!r}", "non_finite")
    if value == 0:
        return "0"  # also -0
    sign = "-" if value < 0 else ""
    # repr() gives the shortest digit string that round-trips (and the
    # closest such string), which is the digit string ECMAScript requires.
    _, digit_tuple, exponent = Decimal(repr(abs(value))).as_tuple()
    assert isinstance(exponent, int)
    digits = "".join(str(d) for d in digit_tuple).lstrip("0")
    # Trailing zeros are not significant (repr(100.0) == "100.0").
    stripped = digits.rstrip("0")
    exponent += len(digits) - len(stripped)
    digits = stripped
    k = len(digits)
    n = k + exponent  # value = 0.digits * 10**n
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
        body = f"{mantissa}e{'+' if e >= 0 else '-'}{abs(e)}"
    return sign + body
