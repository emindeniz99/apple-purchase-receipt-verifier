#!/usr/bin/env python3
"""Evidence only (2026-09-29, round 2): writes the round-2 review's F1
inputs, for `wasm_cost.mjs files`.

    python3 flood_inputs.py OUT-DIR [REPO]

The shared receipt (generated-0.7/receipt.der) with as many two-octet
`30 00` entries as keep it inside the 3 MiB base64 cap added to one of the
three sets the shallow decode keeps as SET OF ANY, one file per set, plus
the 1,057-certificate flood of rust/tests/hostile.rs and junk of the
certificates flood's size. Nothing here is signed anew, but importing
gen_fixtures.py needs the `cryptography` package.
"""

import os
import sys

OUT_DIR = sys.argv[1]
sys.argv = [sys.argv[0]] + sys.argv[2:3]  # gen_fixtures reads REPO from argv[1]
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# gen_fixtures imports `cryptography` at the top; only its DER helpers and
# the shared receipt's parts are used here.
try:
    import gen_fixtures as g
except ImportError as missing:  # pragma: no cover
    sys.exit(f'flood_inputs.py needs what gen_fixtures.py imports: {missing}')

ENTRIES = (2_359_296 - 8_000) // 2
TINY = b'\x30\x00' * ENTRIES


def with_signer_infos(extra):
    """The shared receipt with `extra` appended inside its signerInfos SET."""
    parts = [g.VERSION, g.DIGEST_ALGORITHMS, g.ENCAP[2], g.CERTIFICATES[2],
             g.enc(0x31, g.SIGNER_INFO[2] + extra)]
    return g.seq(g.oid(g.OID_SIGNED_DATA), g.enc(0xa0, g.seq(*parts)))


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    certificates = g.respliced(extra_choices=TINY)
    first = g.children(g.CERTIFICATES[1])[0][2]
    count = len(g.children(g.CERTIFICATES[1]))
    inputs = {
        'r2-flood-certificates.der': certificates,
        'r2-flood-crls.der': g.respliced(crls=g.enc(0xa1, TINY)),
        'r2-flood-signer-infos.der': with_signer_infos(TINY),
        'r2-flood-junk.der': b'\x04' + certificates[1:],
        'r2-flood-1057-certificates.der': g.respliced(extra_choices=first * (1057 - count)),
    }
    for name, der in inputs.items():
        with open(os.path.join(OUT_DIR, name), 'wb') as handle:
            handle.write(der)
        print(name, len(der))


if __name__ == '__main__':
    main()
