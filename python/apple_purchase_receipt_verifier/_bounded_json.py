"""JSON structural bounds, checked before :func:`json.loads` runs: nesting
depth, member-name length and number length. ``json.loads`` has no option
for any of the three and recurses once per nesting level, so an attacker-
chosen document is measured here first, on text nobody has vouched for yet.
The three bounds are the Java port's (``BoundedJson``): 64 levels of nesting,
50,000-character member names, 1,000-character numbers.

This is a bounds scanner, not a validator: malformed JSON that this scanner
cannot make sense of is left for ``json.loads`` to reject on its own terms.
The two must never disagree about what counts as "too deep" for a document
that IS valid JSON, which is the only case this scanner's verdict is acted
on for.
"""

import re

#: How deep an object/array structure may nest, outermost included.
MAX_NESTING_DEPTH = 64
#: The longest object member name, in characters (source form, between the
#: quotes, before unescaping).
MAX_NAME_LENGTH = 50_000
#: The longest number token, in characters.
MAX_NUMBER_LENGTH = 1000

# One alternation, tried left to right: a string, a number, one structural
# character, a literal, whitespace, or (falling through) one otherwise
# unmatched character so the scan always advances.
_TOKEN = re.compile(
    r'"(?P<str>(?:[^"\\]|\\.)*)"'
    r"|(?P<num>-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)"
    r"|(?P<punct>[{}\[\]:,])"
    r"|(?P<lit>true|false|null)"
    r"|(?P<ws>[ \t\r\n]+)"
    r"|(?P<other>.)",
    re.DOTALL,
)


def exceeds_bounds(text: str) -> bool:
    """Whether ``text`` opens more than :data:`MAX_NESTING_DEPTH` objects
    and arrays at once, carries an object member name over
    :data:`MAX_NAME_LENGTH` characters, or a number over
    :data:`MAX_NUMBER_LENGTH` characters."""
    depth = 0
    pending_string_length: int | None = None
    for m in _TOKEN.finditer(text):
        if m.lastgroup == "ws":
            continue
        if m.lastgroup == "str":
            pending_string_length = len(m.group("str"))
            continue
        if m.lastgroup == "num":
            if len(m.group("num")) > MAX_NUMBER_LENGTH:
                return True
            pending_string_length = None
            continue
        if m.lastgroup == "punct":
            punct = m.group("punct")
            if punct in "{[":
                depth += 1
                if depth > MAX_NESTING_DEPTH:
                    return True
            elif punct in "}]":
                depth -= 1
            elif punct == ":":
                if pending_string_length is not None and pending_string_length > MAX_NAME_LENGTH:
                    return True
            pending_string_length = None
            continue
        # "lit" or "other": neither a string nor a number is pending after it.
        pending_string_length = None
    return False
