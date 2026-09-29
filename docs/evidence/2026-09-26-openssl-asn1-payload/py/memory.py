#!/usr/bin/env python3
"""Task 2 criterion "bounded memory": peak RSS and time of each payload
reader on payloads an attacker can hand the PRE-TRUST read (the creation
date is read from the payload before the signature is checked, so the whole
attribute SET is decoded for any receipt that parses as CMS).

    python3 memory.py <out dir> <reader binary>...

Each reader is examples/spike_payload.rs built in one tree; it runs the
pre-trust read and the full parse once each (--raw). Every measurement is a
fresh process: peak RSS is that child's ru_maxrss.

Payloads (all at most 3,145,728 bytes, the receipt cap):
  tiny           one attribute (the process baseline)
  flat-max       SET of 12-byte attributes SEQUENCE{INTEGER 9999, INTEGER 1,
                 OCTET STRING 00} up to the cap (type 9999 is unmodelled, so
                 the full parse keeps every value in unknown_attributes)
  flat-node-cap  the same, 24,999 attributes (just under asn1.rs's 100,000
                 node budget: 1 + 4 per attribute)
  in-app-max     one attribute 17 whose value is a nested SET of those
                 attributes up to the cap
  deep-version   one attribute (type 9999) whose version field is as many
                 nested indefinite-length SEQUENCEs as fit the cap (786,426;
                 asn1.rs refuses a depth over 32)
"""
import os
import resource
import subprocess
import sys
import time

CAP = 3_145_728


def length(n):
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag, body):
    return bytes([tag]) + length(len(body)) + body


ATTR = tlv(0x30, tlv(0x02, b"\x27\x0f") + tlv(0x02, b"\x01") + tlv(0x04, b"\x00"))


def flat(count):
    return tlv(0x31, ATTR * count)


def fit(make, lo, hi):
    """The largest count whose payload fits the cap."""
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if len(make(mid)) <= CAP:
            lo = mid
        else:
            hi = mid - 1
    return lo


def in_app(count):
    inner = flat(count)
    return tlv(0x31, tlv(0x30, tlv(0x02, b"\x11") + tlv(0x02, b"\x01") + tlv(0x04, inner)))


def deep(n):
    version = b"\x30\x80" * n + b"\x00\x00" * n
    return tlv(0x31, tlv(0x30, tlv(0x02, b"\x27\x0f") + version + tlv(0x04, b"\x00")))


def main():
    out, readers = sys.argv[1], sys.argv[2:]
    os.makedirs(out, exist_ok=True)
    payloads = {
        "tiny": flat(1),
        "flat-max": flat(fit(flat, 1, CAP // 12)),
        "flat-node-cap": flat(24_999),
        "in-app-max": in_app(fit(in_app, 1, CAP // 12)),
        "deep-version": deep(fit(deep, 1, CAP // 4) if len(deep(1_000_000)) > CAP else 1_000_000),
    }
    print("# payload | bytes | reader | peak RSS KiB | seconds | verdict")
    for name, data in payloads.items():
        path = os.path.join(out, name)
        with open(path, "wb") as f:
            f.write(data)
        for reader in readers:
            pid = os.fork()
            if pid == 0:
                devnull = os.open(os.devnull, os.O_WRONLY)
                os.dup2(devnull, 2)
                r = subprocess.run([reader, "--raw", path], capture_output=True, text=True)
                started = time.monotonic()
                # One more run, timed, with the same output (the first warms the page cache).
                r = subprocess.run([reader, "--raw", path], capture_output=True, text=True)
                took = time.monotonic() - started
                rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
                cols = r.stdout.rstrip("\n").split("\t")
                verdict = (cols[3][:40] if len(cols) > 3 else r.stdout[:40]) + f" / date {cols[2][:20] if len(cols) > 2 else '?'}"
                print(f"{name} | {len(data)} | {os.path.basename(reader)} | {rss} | {took:.2f} | {verdict}", flush=True)
                os._exit(0)
            os.waitpid(pid, 0)


if __name__ == "__main__":
    main()
