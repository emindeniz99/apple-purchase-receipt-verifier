#!/usr/bin/env python3
"""Task 3: BER spellings of real payloads, to show both readers treat BER in
the PAYLOAD alike (the genuine Xcode receipts are BER only at the CMS level:
their payload SET is definite-length DER).

    python3 ber_variants.py <out dir> <payload file>...

For each DER payload (a definite-length TLV tree) writes:
  <name>.indef      every constructed value re-encoded with indefinite length
  <name>.chunked    every OCTET STRING of 2+ bytes re-encoded as a constructed
                    OCTET STRING of two primitive OCTET STRING chunks (X.690 8.7.3)
  <name>.indef-chunked   both
  <name>.longlen    every length in long form with one extra leading 0x00
                    octet (legal BER, X.690 8.1.3.5 note; not DER)
  <name>.utf8-chunked    every UTF8String/IA5String nested inside an attribute
                    value re-encoded as a constructed string of OCTET STRING
                    chunks: the one BER form the two readers are EXPECTED to
                    disagree on (asn1.rs refuses a constructed string value;
                    OpenSSL accepts constructed forms of string types)
The nested value inside each attribute OCTET STRING is re-encoded too, since
the readers decode it separately.
"""
import os
import sys


def parse(b, i=0, end=None):
    """Definite-length DER TLVs in b[i:end] -> list of (tag, children or bytes)."""
    end = len(b) if end is None else end
    out = []
    while i < end:
        tag = b[i]
        ln = b[i + 1]
        j = i + 2
        if ln & 0x80:
            n = ln & 0x7F
            ln = int.from_bytes(b[j:j + n], "big")
            j += n
        body = b[j:j + ln]
        out.append((tag, parse(body) if tag & 0x20 else body))
        i = j + ln
    return out


def length(n, mode):
    if mode == "longlen":
        raw = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
        raw = b"\x00" + raw
        return bytes([0x80 | len(raw)]) + raw
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def nested(body):
    """An attribute value's own DER, if it parses as exactly one TLV."""
    try:
        tree = parse(body)
        return tree if len(tree) == 1 and enc(tree, "plain") == body else None
    except (IndexError, ValueError):
        return None


def enc(tree, mode, in_value=False):
    out = b""
    for tag, v in tree:
        if isinstance(v, list):
            inner = enc(v, mode, in_value)
            if "indef" in mode:
                out += bytes([tag, 0x80]) + inner + b"\x00\x00"
            else:
                out += bytes([tag]) + length(len(inner), mode) + inner
            continue
        body = v
        if tag == 0x04:
            sub = nested(body)
            if sub is not None:
                body = enc(sub, mode, True)
        if "chunked" in mode and tag == 0x04 and len(body) >= 2 and mode != "utf8-chunked":
            h = len(body) // 2
            chunks = bytes([0x04]) + length(h, mode) + body[:h] + bytes([0x04]) + length(len(body) - h, mode) + body[h:]
            if "indef" in mode:
                out += b"\x24\x80" + chunks + b"\x00\x00"
            else:
                out += b"\x24" + length(len(chunks), mode) + chunks
            continue
        if mode == "utf8-chunked" and in_value and tag in (0x0C, 0x16) and len(body) >= 2:
            h = len(body) // 2
            chunks = b"\x04" + length(h, mode) + body[:h] + b"\x04" + length(len(body) - h, mode) + body[h:]
            out += bytes([tag | 0x20]) + length(len(chunks), mode) + chunks
            continue
        out += bytes([tag]) + length(len(body), mode) + body
    return out


def main():
    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)
    for path in sys.argv[2:]:
        der = open(path, "rb").read()
        tree = parse(der)
        assert enc(tree, "plain") == der, f"{path} is not definite-length DER"
        name = os.path.basename(path)
        for mode in ("indef", "chunked", "indef-chunked", "longlen", "utf8-chunked"):
            with open(os.path.join(out_dir, f"{name}.{mode}"), "wb") as f:
                f.write(enc(tree, mode))


if __name__ == "__main__":
    main()
