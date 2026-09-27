"""Minimal DER TLV reading, for the one thing beyond structural decoding
this library checks about a raw certificate before trusting it: that its
outer ``signatureValue`` BIT STRING declares zero unused bits, as every
X.509 signature (a full byte string — RSA and ECDSA signatures are DER
octet sequences, never a partial final byte) must. ``cryptography`` reads
past a nonzero count here rather than refusing it, so a certificate whose
DER is corrupted exactly there — genuine everywhere else, unusable as an
identity all the way down — would otherwise verify.

Certificates are always definite-length DER (RFC 5280 4.1), so this reader
need not follow BER's indefinite lengths the way ``_asn1_depth`` does for
the CMS envelope.
"""

_TAG_SEQUENCE = 0x30
_TAG_BIT_STRING = 0x03


def _read_tlv(data: bytes, offset: int) -> "tuple[int, bytes, int]":
    if offset + 2 > len(data):
        raise ValueError("truncated ASN.1 value")
    tag = data[offset]
    pos = offset + 1
    length = data[pos]
    pos += 1
    if length >= 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or pos + count > len(data):
            raise ValueError("unsupported ASN.1 length")
        length = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    end = pos + length
    if end > len(data):
        raise ValueError("ASN.1 length exceeds input")
    return tag, data[pos:end], end


def certificate_signature_is_aligned(der: bytes) -> bool:
    """Whether the ``Certificate ::= SEQUENCE { tbsCertificate,
    signatureAlgorithm, signatureValue BIT STRING }``'s third field declares
    zero unused bits. Answers ``True`` (not this check's verdict) for
    anything it cannot follow; the certificate decoder handles that next."""
    try:
        tag, contents, end = _read_tlv(der, 0)
        if tag != _TAG_SEQUENCE or end != len(der):
            return True
        pos = 0
        fields: list[tuple[int, bytes]] = []
        while pos < len(contents) and len(fields) < 3:
            child_tag, child_value, pos = _read_tlv(contents, pos)
            fields.append((child_tag, child_value))
        if len(fields) < 3:
            return True
        signature_tag, signature_value = fields[2]
        if signature_tag != _TAG_BIT_STRING or len(signature_value) == 0:
            return True
        return signature_value[0] == 0
    except Exception:
        return True
