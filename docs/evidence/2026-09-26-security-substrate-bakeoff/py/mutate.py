#!/usr/bin/env python3
"""A brief mutation fuzz corpus: N mutants of the receipt (DER) and JWS rows
of an existing request corpus, same options, deterministic for a seed.

    python3 mutate.py <corpus.jsonl> <n> <seed> > fuzz.jsonl

Mutations, one to three per mutant: flip one bit, set a byte to 0x00, 0x7f,
0x80 or 0xff, add or subtract 1 at a byte (hits length octets as often as
any other byte), delete a range, duplicate a range, truncate, insert random
bytes. JWS mutants mutate the decoded header, payload or signature segment,
or the compact text itself, so both the base64url layer and the certificate
bytes inside x5c are reached. Rows: the corpus row with a new id
"fuzz/<n>/<seed row id>" and a new input.
"""

from __future__ import annotations

import base64
import json
import random
import sys


def mutate_bytes(rng: random.Random, b: bytes) -> bytes:
    b = bytearray(b)
    for _ in range(rng.randint(1, 3)):
        if not b:
            b = bytearray(rng.randbytes(rng.randint(1, 8)))
            continue
        i = rng.randrange(len(b))
        op = rng.randrange(8)
        if op == 0:
            b[i] ^= 1 << rng.randrange(8)
        elif op == 1:
            b[i] = rng.choice((0x00, 0x7F, 0x80, 0xFF))
        elif op == 2:
            b[i] = (b[i] + rng.choice((1, -1))) & 0xFF
        elif op == 3:
            del b[i:i + rng.randint(1, 16)]
        elif op == 4:
            j = min(len(b), i + rng.randint(1, 64))
            b[i:i] = b[i:j]
        elif op == 5:
            del b[i:]
        elif op == 6:
            b[i:i] = rng.randbytes(rng.randint(1, 8))
        else:
            b[i] ^= 0xFF
    return bytes(b)


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def mutate_jws(rng: random.Random, token: bytes) -> bytes:
    parts = token.decode("ascii", "replace").split(".")
    if len(parts) != 3 or rng.random() < 0.2:
        return mutate_bytes(rng, token).replace(b"\0", b"A")
    k = rng.choice((0, 0, 1, 2))
    if k == 0:
        # Mutate inside one x5c certificate most of the time.
        try:
            header = json.loads(unb64url(parts[0]))
            x5c = header.get("x5c") if isinstance(header, dict) else None
            if isinstance(x5c, list) and x5c and all(isinstance(c, str) for c in x5c) and rng.random() < 0.8:
                j = rng.randrange(len(x5c))
                x5c[j] = base64.b64encode(mutate_bytes(rng, base64.b64decode(x5c[j]))).decode()
                parts[0] = b64url(json.dumps(header, separators=(",", ":")).encode())
                return ".".join(parts).encode()
        except (ValueError, UnicodeDecodeError, TypeError):
            pass
    parts[k] = b64url(mutate_bytes(rng, unb64url(parts[k])))
    return ".".join(parts).encode()


def main():
    corpus, n, seed = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    rng = random.Random(seed)
    seeds = []
    for line in open(corpus, encoding="utf-8"):
        if not line.strip():
            continue
        r = json.loads(line)
        if r["kind"] == "receipt" and not r.get("base64") and not r.get("guidHex") \
                and json.loads(r["options"]).get("roots") is not None:
            seeds.append(r)
        elif r["kind"] == "jws" and r.get("op", 0) == 0 and json.loads(r["options"]).get("roots") is not None:
            seeds.append(r)
    for i in range(n):
        r = dict(rng.choice(seeds))
        data = base64.b64decode(r["input"])
        data = mutate_jws(rng, data) if r["kind"] == "jws" else mutate_bytes(rng, data)
        r["id"] = f"fuzz/{i}/{r['id']}"
        r["input"] = base64.b64encode(data).decode()
        print(json.dumps(r, separators=(",", ":")))


if __name__ == "__main__":
    main()
