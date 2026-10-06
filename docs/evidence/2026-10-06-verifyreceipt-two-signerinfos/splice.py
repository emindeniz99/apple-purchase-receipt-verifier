"""Variants of one genuine receipt that change only its SignerInfos.

Every byte outside the signerInfos SET is kept as Apple wrote it; only the
length headers of the three containers around that SET are rewritten. A
re-encoding through an ASN.1 library is not used: BouncyCastle sorts the
certificates SET into DER order, and Apple refuses the receipt for that
alone (control c5 below), which would hide every other answer.

Usage: python3 -I splice.py <receipt.b64> <out dir>
"""
import base64
import os
import sys


def tlv(buf, off):
    """(tag byte, header length, content length) of the value at off; definite lengths only."""
    tag = buf[off]
    first = buf[off + 1]
    if first < 0x80:
        return tag, 2, first
    n = first & 0x7F
    if n == 0:
        raise ValueError("indefinite length at %d" % off)
    return tag, 2 + n, int.from_bytes(buf[off + 2:off + 2 + n], "big")


def children(buf, off):
    """[(offset, total length)] of the values inside the constructed value at off."""
    _, hl, cl = tlv(buf, off)
    out, pos, end = [], off + hl, off + hl + cl
    while pos < end:
        _, h, c = tlv(buf, pos)
        out.append((pos, h + c))
        pos += h + c
    return out


def header(tag, length):
    if length < 0x80:
        return bytes([tag, length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(body)]) + body


def wrap(tag, content):
    return header(tag, len(content)) + content


def main():
    der = base64.b64decode(open(sys.argv[1], "rb").read().strip(), validate=True)
    out = sys.argv[2]
    os.makedirs(out, exist_ok=True)

    content_info = children(der, 0)                # [OID, [0]]
    explicit = content_info[1][0]
    signed_data = children(der, explicit)[0][0]
    fields = children(der, signed_data)            # version, digestAlgs, encap, [0] certs, ([1] crls), SET signerInfos
    set_off, set_len = fields[-1]
    assert der[set_off] == 0x31 and set_off + set_len == len(der)
    infos = children(der, set_off)
    assert len(infos) == 1
    genuine = der[infos[0][0]:infos[0][0] + infos[0][1]]
    before_set = der[signed_data + tlv(der, signed_data)[1]:set_off]

    def receipt(prefix, *signer_infos):
        sd = wrap(0x30, prefix + wrap(0x31, b"".join(signer_infos)))
        return wrap(0x30, der[content_info[0][0]:explicit] + wrap(0xA0, sd))

    # SignerInfo fields: version, sid, digestAlgorithm, [0] signedAttrs, signatureAlgorithm, signature, ...
    si = children(genuine, 0)
    raw = [genuine[o:o + n] for o, n in si]
    unknown_digest = wrap(0x30, raw[0] + raw[1] + wrap(0x30, bytes.fromhex("06032a0304") + bytes.fromhex("0500"))
                          + b"".join(raw[3:]))
    sig_index = 5 if genuine[si[3][0]] == 0xA0 else 4
    flipped = bytearray(raw[sig_index])
    flipped[-1] ^= 1
    bad_signature = wrap(0x30, b"".join(raw[:sig_index]) + bytes(flipped) + b"".join(raw[sig_index + 1:]))

    # Controls.
    same = receipt(before_set, genuine)
    assert same == der, "the splice does not reproduce the original bytes"
    variants = {"c0-original": der}
    encap_off, encap_len = fields[2]
    payload_flipped = bytearray(der)
    payload_flipped[encap_off + encap_len - 1] ^= 1      # last octet of the eContent
    variants["c2-payload-byte-flipped"] = bytes(payload_flipped)
    variants["c3-signature-bit-flipped"] = receipt(before_set, bad_signature)
    variants["c4-unknown-digest-alone"] = receipt(before_set, unknown_digest)
    certs_off, certs_len = fields[3]
    assert der[certs_off] == 0xA0
    certs = children(der, certs_off)
    sorted_certs = sorted((der[o:o + n] for o, n in certs))
    if [der[o:o + n] for o, n in certs] != sorted_certs:
        reordered = der[:certs_off] + wrap(0xA0, b"".join(sorted_certs)) + der[certs_off + certs_len:]
        variants["c5-certificates-in-der-order"] = reordered
    # Two SignerInfos.
    variants["v1-unknown-digest-then-genuine"] = receipt(before_set, unknown_digest, genuine)
    variants["v2-genuine-then-unknown-digest"] = receipt(before_set, genuine, unknown_digest)
    variants["v3-genuine-twice"] = receipt(before_set, genuine, genuine)
    variants["v4-bad-signature-then-genuine"] = receipt(before_set, bad_signature, genuine)
    variants["v5-genuine-then-bad-signature"] = receipt(before_set, genuine, bad_signature)

    for name, data in variants.items():
        with open(os.path.join(out, name + ".b64"), "wb") as f:
            f.write(base64.b64encode(data))


if __name__ == "__main__":
    main()
