#!/usr/bin/env python3
"""Evidence only (2026-09-29, round 3): the most expensive inputs the
envelope's node budget admits (round-3 review F4).

    python3 node_budget_inputs.py OUTDIR

Writes, from the shared generated receipt (generated-0.7/receipt.der):

- genuine.der: the receipt unchanged;
- oids-short.der: the receipt with one unsigned attribute whose SET holds
  as many copies of the OBJECT IDENTIFIER 06 01 2a as keep the envelope at
  100,000 values, the node budget;
- oids-20.der: the same with a 20-octet OBJECT IDENTIFIER (19 octets 0x81
  and 0x01), the reviewer's costliest shape;
- oids-over.der: oids-short.der with one more OBJECT IDENTIFIER, which the
  budget refuses.

The unsigned attribute is outside the signature, so anyone can append it to
any genuine receipt; the first three verify. Time them through aprv.wasm
with `wasm_cost.mjs files <aprv.wasm> fixtures/generated-0.7/receipt-root.der
OUTDIR/*.der`. Imports gen_fixtures.py's writer, which needs `cryptography`
41 or later for its minted PKI.
"""

import os
import sys

OUT_DIR = sys.argv[1] if len(sys.argv) > 1 else None
del sys.argv[1:]  # gen_fixtures.py reads its own first argument as the repository
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_fixtures as g  # noqa: E402  (importing it writes nothing)

BUDGET = 100_000


def count_values(encoding):
    """Every value of the BER `encoding`, primitive ones included, as the
    header walk counts them; the content of a primitive value holds none."""
    ident, body, _, _ = g.tlv(encoding, 0)
    if not ident & 0x20:
        return 1
    return 1 + sum(count_values(whole) for _, _, whole in g.children(body))


def flooded(item, extra=0):
    # The attribute adds four values around the SET's items: [1], the
    # SEQUENCE, the attribute type and the SET.
    count = BUDGET - count_values(g.SHARED) - 4 + extra
    der = g.respliced(unsigned=g.unsigned_attribute(item * count))
    assert count_values(der) == BUDGET + extra
    return der


def main():
    if OUT_DIR is None:
        sys.exit('usage: node_budget_inputs.py OUTDIR')
    out = OUT_DIR
    os.makedirs(out, exist_ok=True)
    short = bytes([0x06, 0x01, 0x2a])
    long = g.enc(0x06, bytes([0x81] * 19 + [0x01]))
    inputs = {
        'genuine': g.SHARED,
        'oids-short': flooded(short),
        'oids-20': flooded(long),
        'oids-over': flooded(short, extra=1),
    }
    for name, der in inputs.items():
        with open(os.path.join(out, name + '.der'), 'wb') as handle:
            handle.write(der)
        print(f'{name}.der {len(der):,} bytes, {count_values(der):,} values')


if __name__ == '__main__':
    main()
