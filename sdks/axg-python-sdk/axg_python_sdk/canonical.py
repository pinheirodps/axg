"""Canonical JSON for payload hashing (Passport v2).

Follows RFC 8785 (JCS) closely enough to be byte-identical across the Python core and the
Python/Node SDKs: keys sorted, no whitespace, UTF-8 without escaping non-ASCII characters, and
numbers serialized the way ECMAScript's Number.prototype.toString does (1500.0 -> "1500").
Integers beyond 2**53 are treated as IEEE-754 doubles (I-JSON), exactly as JavaScript does.
"""

from __future__ import annotations

import hashlib
import json
import math
from decimal import Decimal
from typing import Any

_MAX_SAFE_INTEGER = 2**53 - 1


def _es_number(value: float) -> str:
    """Serialize a float exactly like ECMAScript Number.prototype.toString."""
    if math.isnan(value) or math.isinf(value):
        raise ValueError("NaN and Infinity are not valid JSON numbers")
    if value == 0:
        return "0"

    sign = "-" if value < 0 else ""
    # repr() yields the shortest round-trip digits, the same digits ECMAScript picks
    _, digit_tuple, exponent = Decimal(repr(abs(value))).normalize().as_tuple()
    digits = "".join(map(str, digit_tuple))
    k = len(digits)
    n = exponent + k  # position of the decimal point relative to the digits

    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = f"{digits[:n]}.{digits[n:]}"
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        mantissa = digits if k == 1 else f"{digits[0]}.{digits[1:]}"
        body = f"{mantissa}e{'+' if e >= 0 else '-'}{abs(e)}"
    return sign + body


def _string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def canonical_json(value: Any) -> str:
    """Return the canonical JSON text of a JSON-compatible value."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, int):
        return str(value) if abs(value) <= _MAX_SAFE_INTEGER else _es_number(float(value))
    if isinstance(value, float):
        return _es_number(value)
    if isinstance(value, dict):
        items = sorted((str(k), v) for k, v in value.items())
        return "{" + ",".join(f"{_string(k)}:{canonical_json(v)}" for k, v in items) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(v) for v in value) + "]"
    raise TypeError(f"Unsupported type for canonical JSON: {type(value).__name__}")


def canonical_hash(value: Any) -> str:
    """SHA-256 (hex) of the canonical JSON encoding."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
