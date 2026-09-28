"""Renders attacker-controlled input for a failure message.

Every :class:`~._errors.VerificationError` detail that quotes something out
of the input goes through here first. Truncation keeps a huge claim from
making every message huge; replacing control characters keeps a newline in a
claim from forging the next log line, and a bidirectional override from
reordering the line it sits in. Mirrors the Java port's ``SafeText``.
"""

#: Longer input is cut here. Long enough to identify a claim, short enough
#: to be free.
_MAX_LENGTH = 64

#: The cut for :func:`detail`: a library message quoting two distinguished
#: names still fits, a flood does not.
_MAX_DETAIL_LENGTH = 256

#: Stands in for a character that must not reach a log line as itself.
_PLACEHOLDER = "�"


def _unsafe_in_a_log_line(c: str) -> bool:
    """C0 and C1 controls, DEL, and the Unicode line and paragraph
    separators: everything a log viewer or a line-splitter may treat as a
    break. And the bidirectional formatting characters (U+061C, U+200E,
    U+200F, U+202A to U+202E, U+2066 to U+2069), which can make a log line
    display in an order other than the one it was written in."""
    code = ord(c)
    return (
        code < 0x20
        or 0x7F <= code <= 0x9F
        or code in (0x2028, 0x2029, 0x061C, 0x200E, 0x200F)
        or 0x202A <= code <= 0x202E
        or 0x2066 <= code <= 0x2069
    )


def _render(value: "str | None", max_length: int) -> str:
    if value is None:
        return "null"
    cut = min(len(value), max_length)
    out = [_PLACEHOLDER if _unsafe_in_a_log_line(c) else c for c in value[:cut]]
    text = "".join(out)
    if len(value) > max_length:
        text += f"... ({len(value)} characters)"
    return text


def quote(value: "str | None") -> str:
    """The input, at most ``_MAX_LENGTH`` characters long and carrying no
    control character. A truncated value states its own original length, so
    "this was cut" is never confused with "this was the whole value".
    ``None`` renders as ``"null"``, the same as string interpolation would."""
    return _render(value, _MAX_LENGTH)


def detail(message: "str | None") -> str:
    """A third-party exception message (``cryptography``, ``asn1crypto``)
    rendered as :func:`quote` renders a claim, with a longer cut: such a
    message can quote the input, a distinguished name out of a certificate,
    say, so it is attacker-controlled too."""
    return _render(message, _MAX_DETAIL_LENGTH)
