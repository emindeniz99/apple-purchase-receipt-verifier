"""The ASN.1 nesting bound, checked on the encoding before ``asn1crypto`` or
the strict DER reader builds anything from it.

Ported from the Java port's ``Asn1Depth``: at most :data:`MAX_DEPTH`
constructed values inside one another, the outermost included, and counted
on every encoding this library parses before a signature has vouched for it
(the CMS envelope, and the signed content's attribute SET, each measured on
its own). Both BER (indefinite length, as genuine Apple/Xcode receipts use)
and DER (definite length) are walked, since ``asn1crypto`` parses both.

The walk judges depth and nothing else. An encoding it cannot follow (a
truncated length, say) is not its verdict to give: it answers "not too deep"
and leaves the refusal to the parser that runs next.
"""

#: At most this many constructed values inside one another.
MAX_DEPTH = 64


class _TooDeep(Exception):
    pass


class _Unfollowable(Exception):
    pass


def _walk(der: bytes, at: int, end: int, depth: int) -> int:
    """Walks the value at ``at``, below ``depth`` constructed values already
    open; returns where it ends."""
    if at >= end:
        raise _Unfollowable
    tag = der[at]
    position = at + 1
    if (tag & 0x1F) == 0x1F:
        # A multi-byte tag number: continuation octets have the top bit set.
        while position < end and (der[position] & 0x80) != 0:
            position += 1
        position += 1
    constructed = (tag & 0x20) != 0
    if constructed and depth >= MAX_DEPTH:
        raise _TooDeep
    if position >= end:
        raise _Unfollowable
    first = der[position]
    position += 1
    if first == 0x80:
        if not constructed:
            raise _Unfollowable
        # Indefinite length: children until the end-of-contents octets.
        while True:
            if position + 1 < end and der[position] == 0 and der[position + 1] == 0:
                return position + 2
            position = _walk(der, position, end, depth + 1)
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count > 4 or position + count > end:
            raise _Unfollowable
        length = int.from_bytes(der[position : position + count], "big")
        position += count
    if length > end - position:
        raise _Unfollowable
    content_end = position + length
    if constructed:
        while position < content_end:
            position = _walk(der, position, content_end, depth + 1)
    return content_end


def exceeded(der: bytes) -> bool:
    """Whether ``der`` nests more than :data:`MAX_DEPTH` constructed values."""
    try:
        _walk(der, 0, len(der), 0)
    except _TooDeep:
        return True
    except _Unfollowable:
        return False
    return False
