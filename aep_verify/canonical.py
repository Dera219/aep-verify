"""RFC 8785 (JCS) canonicalization with the AEP §4.1 additions.

AEP §4.1 takes stock JCS and adds three constraints:

* member names and string values are NFC-normalized before serialization
  (an AEP addition; stock JCS does no Unicode normalization);
* every number MUST be an integer: no fraction, no exponent, no negative zero
  (stock JCS serializes any IEEE-754 double);
* member names sort by UTF-16 code unit at every nesting level. This is stock
  RFC 8785 §3.2.3; the §4.1 prose says "Unicode code point", which differs for
  names outside the Basic Multilingual Plane (upstream issue #17). Vector (h)
  and the vectors README pin UTF-16 code units, so that is what this does.

Integers beyond 2**53 - 1 in magnitude are rejected rather than serialized:
RFC 8785 defines number serialization in terms of IEEE-754 doubles, so a
larger integer has no exact canonical form and two implementations could
silently disagree.

Nesting deeper than MAX_DEPTH is also rejected. That limit is this package's,
not RFC 8785's: no AEP hash input comes near it, and without it a hostile
input exhausts the interpreter's stack instead of failing verification.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any

MAX_SAFE_INTEGER = 2**53 - 1
MAX_DEPTH = 128

_TWO_CHAR_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


class CanonicalizationError(ValueError):
    """The value has no AEP-conformant canonical form."""


def _nfc(text: str) -> str:
    return unicodedata.normalize("NFC", text)


def _escape_string(text: str) -> str:
    out = ['"']
    for ch in text:
        esc = _TWO_CHAR_ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_sort_key(name: str) -> bytes:
    # Big-endian UTF-16 bytes compare exactly like the sequence of 16-bit code
    # units, which is the RFC 8785 §3.2.3 member-name order.
    try:
        return name.encode("utf-16-be")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError(f"member name contains a lone surrogate: {name!r}") from exc


def _serialize(value: Any, out: list[str], path: str, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise CanonicalizationError(f"nesting deeper than {MAX_DEPTH} levels at {path[:80]}...")
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalizationError(
                f"integer at {path} exceeds 2**53-1 and has no exact IEEE-754 canonical form"
            )
        out.append(str(value))
    elif isinstance(value, float):
        raise CanonicalizationError(
            f"number at {path} is not an integer ({value!r}); AEP §4.1 hash inputs are integer-only"
        )
    elif isinstance(value, str):
        out.append(_escape_string(_nfc(value)))
    elif isinstance(value, list | tuple):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _serialize(item, out, f"{path}[{i}]", depth + 1)
        out.append("]")
    elif isinstance(value, dict):
        members: list[tuple[str, Any]] = []
        seen: set[str] = set()
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"non-string member name at {path}: {key!r}")
            normalized = _nfc(key)
            if normalized in seen:
                raise CanonicalizationError(
                    f"duplicate member name after NFC normalization at {path}: {normalized!r}"
                )
            seen.add(normalized)
            members.append((normalized, item))
        members.sort(key=lambda kv: _utf16_sort_key(kv[0]))
        out.append("{")
        for i, (key, item) in enumerate(members):
            if i:
                out.append(",")
            out.append(_escape_string(key))
            out.append(":")
            _serialize(item, out, f"{path}.{key}", depth + 1)
        out.append("}")
    else:
        raise CanonicalizationError(f"unsupported value type at {path}: {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    """Return the AEP §4.1 canonical UTF-8 byte stream of a JSON value."""
    out: list[str] = []
    _serialize(value, out, "$")
    try:
        return "".join(out).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError("string contains a lone surrogate") from exc


def sha256_of(value: Any) -> str:
    """'sha256:' + lowercase hex of SHA-256 over the canonical form (§4.1 output format)."""
    return "sha256:" + hashlib.sha256(canonicalize(value)).hexdigest()


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalizationError(f"duplicate member name in JSON text: {key!r}")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise CanonicalizationError(f"non-finite number in JSON text: {name}")


def parse_json(text: str | bytes) -> Any:
    """Parse JSON text strictly enough for evidence: duplicate names and NaN/Infinity are errors.

    Fractional and exponent numbers parse to floats and are rejected later by
    canonicalize(), which is where the §4.1 integer rule is enforced.
    """
    try:
        return json.loads(
            text, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant
        )
    except json.JSONDecodeError as exc:
        raise CanonicalizationError(f"invalid JSON: {exc}") from exc
    except RecursionError as exc:
        raise CanonicalizationError("JSON text is nested too deeply to parse") from exc
