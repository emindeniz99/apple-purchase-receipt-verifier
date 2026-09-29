"""Lane P7-code's probe.py, run against a stub host that records each call as
a tools/differential.sh call row instead of answering it, plus two rows the
note asked for by hand.

    P7_CALLS=out.jsonl python3 calls_from_probe.py <probe.py>

<probe.py> is docs/evidence/2026-09-29-phase7-proposed-cases/probe.py from
lane/phase7-code (commit 4b73900), inside a checkout of the repository, so
its relative paths to fixtures/ and to gen_fixtures.py hold.
"""
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'stub'))
import apple_purchase_receipt_verifier as stub  # noqa: E402  (the stub, ahead of python/)

probe_path = os.path.abspath(sys.argv[1])
sys.argv = [sys.argv[0]]
spec = importlib.util.spec_from_file_location('probe', probe_path)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def propose(case_id, rows, recipe, operation, data, roots, clock=probe.CLOCK_MS, pointers=(), write=None):
    probe.answer(operation, data, roots, clock, pointers)
    row = stub.LAST[0]
    row['id'] = case_id
    stub.CALLS.write(json.dumps(row) + '\n')


probe.propose = propose
probe.main()

# Finding 7 of the note, probed there by hand: a creation date with
# fractional seconds against a signer that expires at the whole second.
start = probe.at(2024, 8, 6, 12, 0, 0)
signer = probe.certificate('P7 Test Signer', probe.SIGNER_KEY, 'P7 Test WWDR', probe.WWDR_KEY, 3,
                           marker=probe.cr.SIGNER_MARKER, validity=(probe.at(2024, 1, 1), start))
probe.receipt_case('receipt/hand-fractional-creation-date-at-not-after', '', '',
                   probe.receipt(probe.payload(created=b'2024-08-06T12:00:00.000Z'), certs=(signer, probe.WWDR)),
                   [probe.ROOT])
# Finding 4: the invalid UTF-8 attribute placed first, so the signed
# attributes SET is in DER order and only the UTF-8 differs from the control.
body = probe.payload()
attrs = [probe.seq(probe.oid('1.2.3.4'), probe.set_of(probe.enc(0x0c, b'\xff\xfe')))] + probe.standard_attrs(body)
probe.receipt_case('receipt/hand-invalid-utf8-signed-attribute-in-der-order', '', '',
                   probe.receipt(body, signed_attrs=attrs), [probe.ROOT])
stub.CALLS.close()
