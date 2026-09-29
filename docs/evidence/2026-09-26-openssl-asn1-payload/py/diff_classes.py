#!/usr/bin/env python3
"""Summarises fuzz/payload-diff.rs's filing directory.

    python3 diff_classes.py <diff dir> [classes.tsv]

One line per signature: filed inputs, the direction (which reader accepts
more), where the culprit is, the old reader's error and OpenSSL's reason on
the culprit, and the shortest filed culprit in hex (truncated). With a
classes file (tab separated: class name, regex over the signature), every
signature is assigned to the first class whose regex matches, and the
per-class totals follow; a signature no class matches is listed as
UNEXPLAINED.
"""
import os
import re
import sys


class OldError(Exception):
    """Where asn1.rs's parse_exact stops: the message, and in `path` the
    child-index path of the node it was reading."""


def old_parse(b, path_out):
    """A Python port of asn1.rs's read_node/parse_exact (MAX_DEPTH 32, a
    100,000-node budget, no multi-byte tags, lengths of at most 4 octets,
    indefinite length only on constructed values, no trailing bytes).
    Returns the tree as (tag, contents, children) tuples."""
    budget = [100_000]

    def node(off, limit, depth, path):
        path_out[:] = path
        if depth > 32:
            raise OldError("maximum ASN.1 nesting depth exceeded")
        if budget[0] == 0:
            raise OldError("ASN.1 node budget exceeded")
        budget[0] -= 1
        if off >= limit:
            raise OldError("truncated ASN.1 value")
        tag = b[off]
        if tag & 0x1F == 0x1F:
            raise OldError("multi-byte ASN.1 tags are not supported")
        cons = bool(tag & 0x20)
        if off + 1 >= limit:
            raise OldError("truncated ASN.1 value")
        lb = b[off + 1]
        pos = off + 2
        if lb < 0x80:
            ln = lb
        elif lb == 0x80:
            if not cons:
                raise OldError("indefinite length on a primitive value")
            ln = None
        else:
            n = lb & 0x7F
            if n > 4 or pos + n > limit:
                raise OldError("unsupported ASN.1 length")
            ln = int.from_bytes(b[pos:pos + n], "big")
            pos += n
        kids = []
        if ln is not None:
            end = pos + ln
            if end > limit:
                raise OldError("ASN.1 length exceeds input")
            if cons:
                i = pos
                while i < end:
                    kid, i = node(i, end, depth + 1, path + [len(kids)])
                    kids.append(kid)
            return (tag, b[pos:end], kids), end
        i = pos
        while True:
            if i + 2 > limit:
                raise OldError("unterminated indefinite-length value")
            if b[i] == 0 and b[i + 1] == 0:
                return (tag, b[pos:i], kids), i + 2
            kid, i = node(i, limit, depth + 1, path + [len(kids)])
            kids.append(kid)

    tree, end = node(0, len(b), 0, [])
    if end != len(b):
        path_out[:] = []
        raise OldError("trailing bytes after ASN.1 value")
    return tree


def octets(n):
    """asn1.rs's octet_string_value: None unless every chunk is an OCTET STRING."""
    tag, contents, kids = n
    if tag == 0x04:
        return contents
    if tag != 0x24:
        return None
    parts = [octets(k) for k in kids]
    return None if any(p is None for p in parts) else b"".join(parts)


FIELDS = {0: "type", 1: "version", 2: "value"}


def where_old_stops(data, prefix=""):
    """Where asn1.rs refuses a payload it cannot walk: which attribute and
    which field (0 type, 1 version, 2 value), looking through the Xcode
    double wrap and into in-app purchase SETs; 'walks' when it does not."""
    path = []
    try:
        tree = old_parse(data, path)
    except OldError as e:
        if len(path) >= 2:
            field = FIELDS.get(path[1], f"field {path[1]}")
            inner = ", inside it" if len(path) > 2 else ""
            return f"{prefix}{e}: {field}{inner}"
        return f"{prefix}{e}: {'an attribute' if path else 'the SET'} itself"
    tag = tree[0]
    if tag in (0x04, 0x24):
        inner = octets(tree)
        if inner is None:
            return f"{prefix}a chunk of the double wrap is not an OCTET STRING"
        return where_old_stops(inner, prefix + "double wrap: ")
    if tag != 0x31:
        return f"{prefix}the outer value is tag {tag:#04x}, not a SET"
    for attr in tree[2]:
        kids = attr[2]
        if attr[0] != 0x30 or len(kids) < 3:
            continue
        if kids[2][0] in (0x04, 0x24) and octets(kids[2]) is None:
            return f"{prefix}a chunk of an attribute value is not an OCTET STRING"
        if kids[0][1] == b"\x11" and octets(kids[2]) is not None:
            got = where_old_stops(octets(kids[2]), prefix + "in-app SET: ")
            if not got.endswith("walks"):
                return got
    return f"{prefix}walks"


def main():
    d = sys.argv[1]
    classes = []
    if len(sys.argv) > 2:
        for line in open(sys.argv[2], encoding="utf-8"):
            if line.strip() and not line.startswith("#"):
                name, rx = line.rstrip("\n").split("\t", 1)
                classes.append((name, re.compile(rx)))
    rows = []
    for sig in sorted(os.listdir(d)):
        files = [f for f in os.listdir(os.path.join(d, sig)) if not f.endswith(".txt")]
        best = None
        for f in files:
            note = open(os.path.join(d, sig, f + ".txt"), encoding="utf-8").read()
            m = re.search(r"culprit \((\d+) bytes\): (\w+)", note)
            if m and (best is None or int(m.group(1)) < best[0]):
                best = (int(m.group(1)), m.group(2))
        where = ""
        if "whole--" in sig:
            # The culprit is a whole (in-app) payload: read the filed inputs
            # themselves (the note keeps only 400 bytes) and say where the
            # old reader stops in the shortest one. For an in-app culprit
            # the filed input is the outer payload, so look inside it.
            shortest = min((open(os.path.join(d, sig, f), "rb").read() for f in files), key=len)
            where = where_old_stops(shortest)
        key = f"{sig} @{where}" if where else sig
        cls = next((name for name, rx in classes if rx.search(key)), "UNEXPLAINED")
        rows.append((cls, key, len(files), best))
    print("# class | filed inputs | signature | shortest culprit (bytes: hex, first 64 bytes)")
    for cls, sig, n, best in sorted(rows):
        hexs = f"{best[0]}: {best[1][:128]}" if best else "-"
        print(f"{cls} | {n} | {sig} | {hexs}")
    if classes:
        print("# per class: signatures, filed inputs")
        totals = {}
        for cls, _, n, _ in rows:
            t = totals.setdefault(cls, [0, 0])
            t[0] += 1
            t[1] += n
        for cls, (s, n) in sorted(totals.items()):
            print(f"# {cls}: {s} signatures, {n} inputs")


if __name__ == "__main__":
    main()
