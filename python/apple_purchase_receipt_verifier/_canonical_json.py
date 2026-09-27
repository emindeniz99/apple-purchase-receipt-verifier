"""Writes the canonical JSON of :meth:`ReceiptPayload.to_json`, the form
every port must produce byte for byte: no whitespace, keys in the order the
caller writes them, and strings escaped as ECMAScript's ``JSON.stringify``
escapes them: ``"`` and ``\\`` as ``\\"`` and ``\\\\``, the short escapes
``\\b \\f \\n \\r \\t``, every other character below U+0020 as a lowercase
``\\u00xx``, and nothing else (``/`` and non-ASCII, U+2028 and U+2029
included, written raw). Unknown attribute keys are written in ascending
numeric order.

Written by hand rather than through :mod:`json` so the escaping is pinned
here rather than to a stdlib default (``json.dumps`` HTML-escapes nothing
extra, but always writes non-ASCII as ``\\uXXXX`` unless ``ensure_ascii``
is turned off, and its default separators include a space); neither is
overridden case by case here, the writer simply never goes through it.
"""

import base64
from collections.abc import Mapping, Sequence

_HEX = "0123456789abcdef"
_SHORT_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def quote(value: str) -> str:
    """A JSON string literal for ``value``."""
    out = ['"']
    for c in value:
        escape = _SHORT_ESCAPES.get(c)
        if escape is not None:
            out.append(escape)
        elif ord(c) < 0x20:
            code = ord(c)
            out.append(f"\\u00{_HEX[(code >> 4) & 0xF]}{_HEX[code & 0xF]}")
        elif 0xD800 <= ord(c) <= 0xDFFF:
            # A lone surrogate: unreachable through this library's own
            # decoders (every string field is decoded from strict UTF-8),
            # but escaped for defence in depth, as JSON.stringify would.
            code = ord(c)
            out.append(f"\\u{_HEX[(code >> 12) & 0xF]}{_HEX[(code >> 8) & 0xF]}")
            out.append(f"{_HEX[(code >> 4) & 0xF]}{_HEX[code & 0xF]}")
        else:
            out.append(c)
    out.append('"')
    return "".join(out)


class ObjectWriter:
    """Accumulates one canonical JSON object's members, in call order."""

    __slots__ = ("_parts",)

    def __init__(self) -> None:
        self._parts: list[str] = []

    def _key(self, key: str) -> None:
        if self._parts:
            self._parts.append(",")
        self._parts.append(quote(key))
        self._parts.append(":")

    def string(self, key: str, value: "str | None") -> "ObjectWriter":
        self._key(key)
        self._parts.append("null" if value is None else quote(value))
        return self

    def number(self, key: str, value: "int | None") -> "ObjectWriter":
        self._key(key)
        self._parts.append("null" if value is None else str(value))
        return self

    def id_(self, key: str, value: "int | None") -> "ObjectWriter":
        """A 64-bit id, written as a JSON string so JavaScript readers do
        not round it."""
        return self.string(key, None if value is None else str(value))

    def bool_(self, key: str, value: "bool | None") -> "ObjectWriter":
        self._key(key)
        self._parts.append("null" if value is None else ("true" if value else "false"))
        return self

    def bytes_(self, key: str, value: "bytes | None") -> "ObjectWriter":
        return self.string(key, None if value is None else base64.b64encode(value).decode("ascii"))

    def raw(self, key: str, raw_json: str) -> "ObjectWriter":
        """``raw_json`` is inserted verbatim as the value; the caller built
        it (an array of nested objects, say)."""
        self._key(key)
        self._parts.append(raw_json)
        return self

    def attributes(self, key: str, attributes: "Mapping[int, Sequence[bytes]]") -> "ObjectWriter":
        """``{"9": ["<base64>", ...], "13": [...]}``: keys in ascending
        numeric order, each key's values in the order the sequence holds
        them."""
        self._key(key)
        parts = ["{"]
        for i, attr_type in enumerate(sorted(attributes)):
            if i:
                parts.append(",")
            parts.append(quote(str(attr_type)))
            parts.append(":[")
            for j, value in enumerate(attributes[attr_type]):
                if j:
                    parts.append(",")
                parts.append(quote(base64.b64encode(value).decode("ascii")))
            parts.append("]")
        parts.append("}")
        self._parts.append("".join(parts))
        return self

    def build(self) -> str:
        return "{" + "".join(self._parts) + "}"
