#!/usr/bin/env python3
"""Seeds for the two payload targets, derived from the fixtures at run time.

    derive-seeds.py receipt-payload <out-dir> <dir>...
    derive-seeds.py jws-payload <out-dir> <dir>...

receipt-payload: every file under the directories that is a CMS
SignedData, as DER/BER or as base64 text, gives its eContent octets (the
bytes the signature covers, chunks of a constructed OCTET STRING joined).
jws-payload: every file that is a compact JWS gives its decoded payload
segment. Each seed is written as <out-dir>/<sha1 of its bytes>, as
libFuzzer names corpus units, so a rerun adds nothing twice.

The fixtures stay the one copy of these bytes: nothing derived here is
committed (run.sh writes into the gitignored corpus/ directory). A file
that is not the expected shape is skipped, as many fixtures are broken on
purpose. Exits 1 if no file gave a seed, so a moved fixture directory
fails loudly instead of fuzzing from nothing.

Standard library only, so it runs on a CI runner and in OSS-Fuzz's
builder image alike.
"""

import base64
import binascii
import hashlib
import os
import re
import sys

BASE64 = re.compile(rb"[A-Za-z0-9+/]+={0,2}")
BASE64URL = re.compile(rb"[A-Za-z0-9_-]*")


class Shape(Exception):
    """Not the shape this script reads."""


def header(buf, at):
    """(tag octet, constructed, content start, content end or None)."""
    if at + 2 > len(buf):
        raise Shape()
    first = buf[at]
    at += 1
    if first & 0x1F == 0x1F:  # high tag number form
        while True:
            if at >= len(buf):
                raise Shape()
            at += 1
            if buf[at - 1] & 0x80 == 0:
                break
    if at >= len(buf):
        raise Shape()
    length = buf[at]
    at += 1
    constructed = bool(first & 0x20)
    if length == 0x80:
        if not constructed:
            raise Shape()
        return first, constructed, at, None
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or at + count > len(buf):
            raise Shape()
        length = int.from_bytes(buf[at : at + count], "big")
        at += count
    if at + length > len(buf):
        raise Shape()
    return first, constructed, at, at + length


def element(buf, at, depth=0):
    """(tag, constructed, start, end, children or None, next offset)."""
    if depth > 64:
        raise Shape()
    tag, constructed, start, end = header(buf, at)
    children = None
    if constructed:
        children = []
        cursor = start
        while True:
            if end is None:
                if buf[cursor : cursor + 2] == b"\x00\x00":
                    end = cursor
                    after = cursor + 2
                    break
            elif cursor >= end:
                after = end
                break
            child = element(buf, cursor, depth + 1)
            children.append(child)
            cursor = child[5]
            if end is not None and cursor > end:
                raise Shape()
    else:
        after = end
    return tag, constructed, start, end, children, after


def octets(buf, node):
    """An OCTET STRING's contents, chunks of a constructed one joined."""
    tag, constructed, start, end, children, _ = node
    if not constructed:
        return buf[start:end]
    return b"".join(octets(buf, child) for child in children)


def econtent(der):
    """The eContent of a ContentInfo holding a SignedData."""
    content_info = element(der, 0)
    if content_info[0] != 0x30 or len(content_info[4]) < 2:
        raise Shape()
    explicit = content_info[4][1]
    if explicit[0] != 0xA0 or not explicit[4]:
        raise Shape()
    signed_data = explicit[4][0]
    if signed_data[0] != 0x30 or len(signed_data[4]) < 3:
        raise Shape()
    encap = signed_data[4][2]
    if encap[0] != 0x30 or len(encap[4]) < 2 or encap[4][1][0] != 0xA0:
        raise Shape()
    wrapped = encap[4][1][4]
    if not wrapped or wrapped[0][0] not in (0x04, 0x24):
        raise Shape()
    return octets(der, wrapped[0])


def receipt_seeds(data):
    candidates = [data]
    text = b"".join(data.split())
    if BASE64.fullmatch(text):
        try:
            candidates.append(base64.b64decode(text, validate=True))
        except binascii.Error:
            pass
    for der in candidates:
        try:
            yield econtent(der)
        except (Shape, IndexError, TypeError):
            continue


def jws_seeds(data):
    parts = data.strip().split(b".")
    if len(parts) != 3 or not all(BASE64URL.fullmatch(part) for part in parts):
        return
    segment = parts[1]
    try:
        yield base64.urlsafe_b64decode(segment + b"=" * (-len(segment) % 4))
    except binascii.Error:
        return


def main(argv):
    if len(argv) < 4 or argv[1] not in ("receipt-payload", "jws-payload"):
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    derive = receipt_seeds if argv[1] == "receipt-payload" else jws_seeds
    out = argv[2]
    os.makedirs(out, exist_ok=True)
    written = set()
    for top in argv[3:]:
        for root, dirs, files in os.walk(top):
            dirs.sort()
            for name in sorted(files):
                with open(os.path.join(root, name), "rb") as handle:
                    data = handle.read()
                for seed in derive(data):
                    digest = hashlib.sha1(seed).hexdigest()
                    if digest not in written:
                        with open(os.path.join(out, digest), "wb") as handle:
                            handle.write(seed)
                        written.add(digest)
    if not written:
        print(f"derive-seeds: no {argv[1]} seed under {argv[3:]}", file=sys.stderr)
        return 1
    print(f"derive-seeds: {len(written)} {argv[1]} seeds in {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
