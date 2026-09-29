#!/usr/bin/env python3
"""Trust-store isolation inputs: a receipt and a JWS whose chains end at a
root the request does NOT pin, plus that root planted everywhere an
OpenSSL-family library could look on its own:

    OUT/ambient.pem          for SSL_CERT_FILE
    OUT/certdir/<hash>.0     for SSL_CERT_DIR (hash names from `openssl x509 -hash`)
    OUT/openssl.cnf          for OPENSSL_CONF: loads a provider module that
                             does not exist and sets default properties no
                             provider satisfies, so a library that reads it
                             either fails to initialise or fails every digest
    OUT/isolation.jsonl      the requests (pinned root: an unrelated one)
    OUT/receipt.der, OUT/transaction.jws, OUT/pinned-other.der,
    OUT/receipt-root.der, OUT/jws-root.der
                             the same inputs as files, for c/run1.c

A verifier that stays inside its pinned roots answers 4 (INVALID_CHAIN) to
both requests and never opens any of those paths.

    python3 gen_isolation.py OUT
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_corpus as g  # noqa: E402


def main():
    out = Path(sys.argv[1])
    (out / "certdir").mkdir(parents=True, exist_ok=True)
    rp, jp = g.Pki("receipt", tag="ambient"), g.Pki("jws", tag="ambient")
    other = g.Pki("receipt", tag="pinned")
    pems = []
    for cert in (rp.root.der, jp.root.der):
        pem = subprocess.run(["openssl", "x509", "-inform", "der"], input=cert, capture_output=True, check=True).stdout
        pems.append(pem)
        digest = subprocess.run(["openssl", "x509", "-noout", "-hash"], input=pem, capture_output=True,
                                check=True).stdout.decode().strip()
        (out / "certdir" / f"{digest}.0").write_bytes(pem)
    (out / "ambient.pem").write_bytes(b"".join(pems))
    (out / "openssl.cnf").write_text(
        "openssl_conf = hostile\n"
        "[hostile]\nproviders = prov\nalg_section = algs\n"
        "[prov]\nbogus = bogus_sect\n"
        "[bogus_sect]\nmodule = /nonexistent/aprv-hostile-provider.so\nactivate = 1\n"
        "[algs]\ndefault_properties = provider=aprv-does-not-exist\n"
    )
    receipt_der, token = g.receipt(rp), g.jws(jp, g.SIGNED)
    (out / "receipt.der").write_bytes(receipt_der)
    (out / "transaction.jws").write_bytes(token)
    (out / "pinned-other.der").write_bytes(other.root.der)
    (out / "receipt-root.der").write_bytes(rp.root.der)
    (out / "jws-root.der").write_bytes(jp.root.der)
    g.ROWS.clear()
    g.emit("isolation/receipt-under-ambient-root", "receipt", receipt_der, other.roots())
    g.emit("isolation/jws-under-ambient-root", "jws", token, other.roots())
    # Controls: the same inputs with their own root pinned must verify.
    g.emit("isolation/receipt-control", "receipt", receipt_der, rp.roots())
    g.emit("isolation/jws-control", "jws", token, jp.roots())
    with open(out / "isolation.jsonl", "w", encoding="utf-8") as f:
        for row in g.ROWS:
            f.write(json.dumps(row, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
