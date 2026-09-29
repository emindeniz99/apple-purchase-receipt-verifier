"""The round-3 two-chunk certificate signature in three spellings, as differential calls."""
import base64, json, os, sys
sys.path.insert(0, os.path.join(sys.argv[1], 'docs/evidence/2026-09-29-core-review-fixes'))
sys.argv = [sys.argv[0]]
import gen_fixtures as g

certificates = [whole for _, _, whole in g.children(g.CERTIFICATES[1])]
root = open(os.path.join(g.FIXTURES, 'generated-0.7/receipt-root.der'), 'rb').read()

def rechunk(certificate, chunks):
    tbs, algorithm, bits = g.children(g.tlv(certificate, 0)[1])
    return g.seq(tbs[2], algorithm[2], g.enc(0x23, b''.join(chunks(bits[1]))))

variants = {
    # The case: the second chunk carries no initial octet of its own (OpenSSL's reading).
    'openssl-raw-join': lambda c: [g.enc(0x03, b'\x00'), g.enc(0x03, c[1:])],
    # X.690 8.6.4: every segment is a bitstring encoding with its own initial octet.
    'x690-two-segments': lambda c: [g.enc(0x03, b'\x00'), g.enc(0x03, c)],
    # One segment: both readings agree.
    'one-segment': lambda c: [g.enc(0x03, c)],
}
for label, chunks in variants.items():
    bag = [rechunk(certificates[0], chunks)] + certificates[1:]
    signed_data = g.seq(g.VERSION, g.DIGEST_ALGORITHMS, g.ENCAP[2], g.enc(0xa0, b''.join(bag)), g.SIGNER_INFOS[2])
    der = g.seq(g.oid(g.OID_SIGNED_DATA), g.enc(0xa0, signed_data))
    text = base64.b64encode(der)
    print(json.dumps({'id': 'bitstring/' + label, 'fn': 'verify-receipt',
                      'config': json.dumps({'roots': [base64.b64encode(root).decode()]}),
                      'now': 1735689600000, 'b64': base64.b64encode(text).decode()}))
