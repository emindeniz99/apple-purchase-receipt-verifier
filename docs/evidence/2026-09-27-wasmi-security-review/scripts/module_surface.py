#!/usr/bin/env python3
"""Spike only (2026-09-27). Print the parts of a Wasm module that decide
which Wasmi code paths it can reach: imports, memories (defined and
imported), tables and the start function.

Usage: module_surface.py MODULE.wasm   (standard library only)

It walks section headers and the import, table and memory bodies. It does
not disassemble code.
"""
import hashlib
import sys


def leb(buf, i):
    r = s = 0
    while True:
        b = buf[i]
        i += 1
        r |= (b & 0x7F) << s
        s += 7
        if b < 0x80:
            return r, i


def name(buf, i):
    n, i = leb(buf, i)
    return buf[i:i + n].decode("utf-8", "replace"), i + n


def limits(buf, i):
    flags = buf[i]
    i += 1
    lo, i = leb(buf, i)
    hi = None
    if flags & 1:
        hi, i = leb(buf, i)
    return (flags, lo, hi), i


def main():
    data = open(sys.argv[1], "rb").read()
    print(f"size {len(data)} bytes, sha256 {hashlib.sha256(data).hexdigest()}")
    assert data[:8] == b"\0asm\x01\0\0\0"
    i = 8
    mem_imports = []
    while i < len(data):
        sid = data[i]
        size, j = leb(data, i + 1)
        body = data[j:j + size]
        if sid == 2:
            n, k = leb(body, 0)
            print(f"imports: {n}")
            for _ in range(n):
                mod, k = name(body, k)
                fld, k = name(body, k)
                kind = body[k]
                k += 1
                if kind == 0:
                    t, k = leb(body, k)
                    print(f"  func   {mod}.{fld} (type {t})")
                elif kind == 1:
                    k += 1
                    lim, k = limits(body, k)
                    print(f"  table  {mod}.{fld} {lim}")
                elif kind == 2:
                    lim, k = limits(body, k)
                    mem_imports.append((mod, fld))
                    print(f"  memory {mod}.{fld} {lim}")
                elif kind == 3:
                    k += 2
                    print(f"  global {mod}.{fld}")
        elif sid == 4:
            n, k = leb(body, 0)
            print(f"tables defined: {n}")
            for _ in range(n):
                k += 1
                lim, k = limits(body, k)
                print(f"  table {lim}")
        elif sid == 5:
            n, k = leb(body, 0)
            print(f"memories defined: {n}")
            for _ in range(n):
                lim, k = limits(body, k)
                print(f"  memory (flags, min pages, max pages) {lim}")
        elif sid == 8:
            print("start function: present")
        elif sid == 10:
            print(f"code section: {size} bytes")
        i = j + size
    print(f"memory imports: {len(mem_imports)}")


if __name__ == "__main__":
    main()
