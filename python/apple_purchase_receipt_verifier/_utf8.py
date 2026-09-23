"""UTF-8 byte length of a request string, the unit Apple's input limits
count in."""


def utf8_exceeds(text: str, limit: int) -> bool:
    """Whether ``text`` takes more than ``limit`` bytes as UTF-8.

    A Python ``str`` holds code points, and each one costs one to four bytes,
    so ``len`` decides most calls without looking at a character: more code
    points than the limit is over it, and four times the code points within
    the limit is within it. An ASCII string (``isascii`` is a flag lookup in
    CPython) is exactly its length in bytes.

    Only a non-ASCII string between those bounds is encoded to be counted.
    That copy is at most four times the limit and runs in C; a Python loop
    that could stop early copies nothing but takes about a hundred times as
    long over a string of this size, which is the worse cost to hand a
    hostile caller. ``surrogatepass`` counts a lone surrogate as three bytes,
    as the Java port does; the conformance vectors carry none, so the ports
    need not agree on it."""
    length = len(text)
    if length > limit:
        return True
    if length * 4 <= limit:
        return False
    if text.isascii():
        return False
    return len(text.encode("utf-8", "surrogatepass")) > limit
