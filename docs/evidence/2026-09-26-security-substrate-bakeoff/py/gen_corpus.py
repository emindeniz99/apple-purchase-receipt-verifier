#!/usr/bin/env python3
"""Writes the substrate corpus: receipts and JWS built from a test PKI this
script generates, aimed at the places a security library and the Java
reference can disagree. JSON lines in the previous spike's request format,
so OracleCli (Java), run_rust.py (every C ABI build) and tri.py read it
unchanged.

    python3 gen_corpus.py $REPO/fixtures > $SCRATCH/corpora/substrate.jsonl

Groups (the id prefix):
  time/    certificate validity judged at a signing instant, at whole
           seconds and millisecond offsets around notBefore and notAfter,
           before 1970 and across the UTCTime/GeneralizedTime switch
  cms/     SignedData and SignerInfo shapes: several SignerInfos, a
           digestAlgorithms set that does not name the signer's digest,
           duplicate or unsorted signed attributes, BER in places DER is
           expected, SKI signer identifiers, CRLs
  pkix/    path rules: CA flags, path length, key usage, unknown critical
           extensions, name comparison, serials, weak keys and digests,
           trust anchors that are not self-signed roots
  flood/   counts: certificates, SignerInfos, attributes
  parse/   bytes: truncation, trailing data, huge lengths, deep nesting,
           non-minimal lengths, on a generated receipt and on the genuine
           public sandbox receipt

Needs the `cryptography` package (keys and signatures only; every
structure is encoded here, so it can be wrong on purpose). Keys are fresh
on every run, so the Java oracle must run on the same output file.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

BUNDLE = "com.example.substrate"

# --- DER / BER encoding -----------------------------------------------------


def length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + length(len(content)) + content


def indef(tag: int, content: bytes) -> bytes:
    return bytes([tag, 0x80]) + content + b"\x00\x00"


def seq(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def set_of(*items: bytes, sort: bool = True) -> bytes:
    return tlv(0x31, b"".join(sorted(items) if sort else items))


def integer(n: int) -> bytes:
    size = max(1, (n.bit_length() + 8) // 8) if n >= 0 else max(1, ((-n - 1).bit_length() + 8) // 8)
    return tlv(0x02, n.to_bytes(size, "big", signed=True))


def oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    out = bytearray()
    for i, value in enumerate([parts[0] * 40 + parts[1]] + parts[2:]):
        chunk = [value & 0x7F]
        value >>= 7
        while value:
            chunk.append(0x80 | (value & 0x7F))
            value >>= 7
        out += bytes(reversed(chunk))
    return tlv(0x06, bytes(out))


def octets(b: bytes) -> bytes:
    return tlv(0x04, b)


def null() -> bytes:
    return b"\x05\x00"


def bits(b: bytes) -> bytes:
    return tlv(0x03, b"\x00" + b)


def ctx(n: int, content: bytes, constructed: bool = True) -> bytes:
    return tlv((0xA0 if constructed else 0x80) | n, content)


def text(s: str, kind: str = "utf8") -> bytes:
    return tlv({"utf8": 0x0C, "printable": 0x13, "ia5": 0x16}[kind], s.encode())


def at(iso: str) -> int:
    """Unix milliseconds of an ISO-8601 UTC instant."""
    return int(dt.datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp() * 1000)


def iso_millis(ms: int) -> str:
    moment = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(milliseconds=ms)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def x509_time(ms: int) -> bytes:
    moment = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(milliseconds=ms)
    if 1950 <= moment.year < 2050:
        return tlv(0x17, moment.strftime("%y%m%d%H%M%SZ").encode())
    return tlv(0x18, moment.strftime("%Y%m%d%H%M%SZ").encode())


# --- OIDs -----------------------------------------------------------------

CN = "2.5.4.3"
RSA_ENC = "1.2.840.113549.1.1.1"
SHA256_RSA = "1.2.840.113549.1.1.11"
SHA1_RSA = "1.2.840.113549.1.1.5"
MD5_RSA = "1.2.840.113549.1.1.4"
ECDSA_SHA256 = "1.2.840.10045.4.3.2"
SHA256 = "2.16.840.1.101.3.4.2.1"
SHA512 = "2.16.840.1.101.3.4.2.3"
SHA1 = "1.3.14.3.2.26"
DATA = "1.2.840.113549.1.7.1"
SIGNED_DATA = "1.2.840.113549.1.7.2"
CONTENT_TYPE = "1.2.840.113549.1.9.3"
MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
SIGNING_TIME = "1.2.840.113549.1.9.5"
BASIC_CONSTRAINTS = "2.5.29.19"
KEY_USAGE = "2.5.29.15"
EXT_KEY_USAGE = "2.5.29.37"
SKI = "2.5.29.14"
AKI = "2.5.29.35"
RECEIPT_MARKER = "1.2.840.113635.100.6.11.1"
LEAF_MARKER = "1.2.840.113635.100.6.11.1"
WWDR_MARKER = "1.2.840.113635.100.6.2.1"

SIG = {
    "sha256-rsa": (SHA256_RSA, hashes.SHA256(), True),
    "sha1-rsa": (SHA1_RSA, hashes.SHA1(), True),
    "md5-rsa": (MD5_RSA, hashes.MD5(), True),
    "sha256-ecdsa": (ECDSA_SHA256, hashes.SHA256(), False),
}

# --- keys and certificates ------------------------------------------------

_RSA_CACHE: list = []


def rsa_key(bits: int = 2048):
    if bits == 2048 and len(_RSA_CACHE) > 24:
        # Plenty of distinct keys already; reuse keeps generation fast.
        _RSA_CACHE.append(_RSA_CACHE.pop(0))
        return _RSA_CACHE[-1]
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    if bits == 2048:
        _RSA_CACHE.append(key)
    return key


def ec_key(curve=None):
    return ec.generate_private_key(curve or ec.SECP256R1())


def spki(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def key_id(key) -> bytes:
    return hashlib.sha1(spki(key)).digest()


def sign(key, data: bytes, alg: str) -> bytes:
    _, digest, is_rsa = SIG[alg]
    if is_rsa:
        return key.sign(data, padding.PKCS1v15(), digest)
    return key.sign(data, ec.ECDSA(digest))


def name(cn: str, kind: str = "utf8") -> bytes:
    return seq(set_of(seq(oid(CN), text(cn, kind))))


def ext(dotted: str, value: bytes, critical: bool = False) -> bytes:
    return seq(oid(dotted), b"\x01\x01\xff" if critical else b"", octets(value))


def basic_constraints(ca: bool, path_len: int | None = None) -> bytes:
    body = (b"\x01\x01\xff" if ca else b"") + (integer(path_len) if path_len is not None else b"")
    return ext(BASIC_CONSTRAINTS, seq(body) if body else seq(), critical=True)


def key_usage(bits_value: int, unused: int) -> bytes:
    # bits_value is the first octet, most significant bit = digitalSignature
    return ext(KEY_USAGE, tlv(0x03, bytes([unused, bits_value])), critical=True)


class Cert:
    def __init__(self, der: bytes, key, subject: bytes, serial: int):
        self.der, self.key, self.subject, self.serial = der, key, subject, serial


_SERIAL = [1000]


def make_cert(subject: bytes, key, issuer: bytes, issuer_key, nb: int, na: int, exts: list[bytes] | None,
              alg: str | None = None, serial: int | None = None, version: int = 2) -> Cert:
    if serial is None:
        _SERIAL[0] += 1
        serial = _SERIAL[0]
    if alg is None:
        alg = "sha256-rsa" if isinstance(issuer_key, rsa.RSAPrivateKey) else "sha256-ecdsa"
    algid = seq(oid(SIG[alg][0]), null()) if SIG[alg][2] else seq(oid(SIG[alg][0]))
    tbs = seq(
        ctx(0, integer(version)) if version else b"",
        integer(serial),
        algid,
        issuer,
        seq(x509_time(nb), x509_time(na)),
        subject,
        spki(key),
        ctx(3, seq(*exts)) if exts else b"",
    )
    der = seq(tbs, algid, bits(sign(issuer_key, tbs, alg)))
    return Cert(der, key, subject, serial)


WIDE = (at("2020-01-01T00:00:00Z"), at("2040-01-01T00:00:00Z"))
LEAF = (at("2025-01-01T00:00:00Z"), at("2025-12-31T23:59:59Z"))
SIGNED = at("2025-06-01T00:00:00Z")


class Pki:
    """root -> intermediate -> signer, RSA for receipts or EC for JWS."""

    def __init__(self, kind: str = "receipt", root_win=WIDE, inter_win=WIDE, leaf_win=LEAF,
                 inter_exts=None, leaf_exts=None, root_exts=None, leaf_key=None, alg=None,
                 inter_issuer_name=None, leaf_issuer_name=None, leaf_serial=None, inter_version=2,
                 tag=""):
        gen = rsa_key if kind == "receipt" else ec_key
        self.kind = kind
        self.root_key, self.inter_key = gen(), gen()
        self.leaf_key = leaf_key or gen()
        root_name = name(f"Substrate Root {tag}".strip())
        inter_name = name(f"Substrate CA {tag}".strip())
        leaf_name = name(f"Substrate Signer {tag}".strip())
        marker = [ext(RECEIPT_MARKER, null())] if kind == "receipt" else [ext(LEAF_MARKER, null())]
        inter_marker = [] if kind == "receipt" else [ext(WWDR_MARKER, null())]
        self.root = make_cert(root_name, self.root_key, root_name, self.root_key, *root_win,
                              root_exts if root_exts is not None else [basic_constraints(True)], alg)
        self.inter = make_cert(inter_name, self.inter_key, inter_issuer_name or root_name, self.root_key, *inter_win,
                               (inter_exts if inter_exts is not None else [basic_constraints(True)]) + inter_marker,
                               alg, version=inter_version)
        self.leaf = make_cert(leaf_name, self.leaf_key, leaf_issuer_name or inter_name, self.inter_key, *leaf_win,
                              (leaf_exts if leaf_exts is not None else [basic_constraints(False)]) + marker,
                              alg, serial=leaf_serial)

    def roots(self):
        return [self.root.der]


# --- receipts ---------------------------------------------------------------


def payload_attr(kind: int, value: bytes) -> bytes:
    return seq(integer(kind), integer(1), octets(value))


def receipt_payload(creation: str | None) -> bytes:
    attrs = [
        payload_attr(0, text("ProductionSandbox")),
        payload_attr(2, text(BUNDLE)),
        payload_attr(3, text("1.0")),
        payload_attr(4, b"\x01\x02\x03\x04"),
        payload_attr(5, bytes(20)),
        payload_attr(19, text("1.0")),
    ]
    if creation is not None:
        attrs.append(payload_attr(12, text(creation, "ia5")))
    return set_of(*attrs)


def algid(dotted: str, with_null: bool = True) -> bytes:
    return seq(oid(dotted), null() if with_null else b"")


def signer_info(signer: Cert, key, content: bytes, *, attrs: list[bytes] | None = "default",
                signed_time: int = SIGNED, e_content_type: str = DATA, sort_attrs: bool = True,
                sign_sorted: bool = True, attrs_indefinite: bool = False, digest=SHA256,
                digest_null: bool = True, sig_alg_oid: str = RSA_ENC, unsigned: bytes | None = None,
                sid: bytes | None = None, version: int = 1, corrupt: bool = False,
                issuer: bytes | None = None, alg: str = "sha256-rsa") -> bytes:
    hash_fn = {SHA256: hashlib.sha256, SHA1: hashlib.sha1, SHA512: hashlib.sha512}[digest]
    if attrs == "default":
        attrs = [
            seq(oid(CONTENT_TYPE), set_of(oid(e_content_type))),
            seq(oid(SIGNING_TIME), set_of(x509_time(signed_time))),
            seq(oid(MESSAGE_DIGEST), set_of(octets(hash_fn(content).digest()))),
        ]
    if attrs is None:
        signature = sign(key, content, alg)
        attr_field = b""
    else:
        as_sent = b"".join(sorted(attrs) if sort_attrs else attrs)
        covered = set_of(*attrs, sort=True) if sign_sorted else tlv(0x31, as_sent)
        signature = sign(key, covered, alg)
        attr_field = indef(0xA0, as_sent) if attrs_indefinite else ctx(0, as_sent)
    if corrupt:
        signature = bytes([signature[0] ^ 0xFF]) + signature[1:]
    if sid is None:
        issuer_name = issuer if issuer is not None else signer_issuer(signer)
        sid = seq(issuer_name, integer(signer.serial))
    return seq(
        integer(version),
        sid,
        algid(digest, digest_null),
        attr_field,
        algid(sig_alg_oid),
        octets(signature),
        ctx(1, unsigned) if unsigned is not None else b"",
    )


def signer_issuer(cert: Cert) -> bytes:
    """The issuer Name, read back out of the certificate DER."""
    return _issuer_of(cert.der)


def der_children(der: bytes) -> list[bytes]:
    """Children of a definite-length constructed TLV (DER only)."""
    _, header, total = read_header(der, 0)
    out, pos = [], header
    while pos < total:
        _, h, t = read_header(der, pos)
        out.append(der[pos:pos + t])
        pos += t
    return out


def read_header(der: bytes, pos: int):
    tag = der[pos]
    first = der[pos + 1]
    if first < 0x80:
        return tag, 2, 2 + first
    n = first & 0x7F
    size = int.from_bytes(der[pos + 2:pos + 2 + n], "big")
    return tag, 2 + n, 2 + n + size


def _issuer_of(cert_der: bytes) -> bytes:
    tbs = der_children(cert_der)[0]
    fields = der_children(tbs)
    offset = 1 if fields[0][0] == 0xA0 else 0
    return fields[offset + 2]


def signed_data(content: bytes, certs: list[bytes], infos: list[bytes], *, digest_algs: list[bytes] | None = None,
                e_content_type: str = DATA, content_field: bytes | None = None, crls: bytes | None = None,
                version: int = 1, ber: bool = True) -> bytes:
    if digest_algs is None:
        digest_algs = [algid(SHA256)]
    if content_field is None:
        content_field = octets(content)
    if ber:
        encap = indef(0x30, oid(e_content_type) + indef(0xA0, content_field))
        body = (integer(version) + set_of(*digest_algs) + encap
                + (indef(0xA0, b"".join(certs)) if certs else b"")
                + (ctx(1, crls) if crls is not None else b"")
                + set_of(*infos, sort=False))
        return indef(0x30, oid(SIGNED_DATA) + indef(0xA0, indef(0x30, body)))
    encap = seq(oid(e_content_type), ctx(0, content_field))
    body = (integer(version) + set_of(*digest_algs) + encap
            + (ctx(0, b"".join(certs)) if certs else b"")
            + (ctx(1, crls) if crls is not None else b"")
            + set_of(*infos, sort=False))
    return seq(oid(SIGNED_DATA), ctx(0, seq(body)))


def receipt(pki: Pki, creation: str | None = "2025-06-01T00:00:00Z", certs: list[bytes] | None = None,
            infos: list[bytes] | None = None, **kw) -> bytes:
    content = receipt_payload(creation)
    si_kw = {k[3:]: v for k, v in kw.items() if k.startswith("si_")}
    sd_kw = {k[3:]: v for k, v in kw.items() if k.startswith("sd_")}
    if infos is None:
        infos = [signer_info(pki.leaf, pki.leaf_key, content, **si_kw)]
    if certs is None:
        certs = [pki.leaf.der, pki.inter.der]
    return signed_data(content, certs, infos, **sd_kw)


# --- JWS ------------------------------------------------------------------


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jws(pki: Pki, signed_date: int | None, x5c: list[bytes] | None = None) -> bytes:
    header = {"alg": "ES256", "x5c": [b64(c) for c in (x5c or [pki.leaf.der, pki.inter.der, pki.root.der])]}
    claims = {"bundleId": "com.example.app", "environment": "Sandbox", "transactionId": "1"}
    if signed_date is not None:
        claims["signedDate"] = signed_date
    signing_input = (b64url(json.dumps(header, separators=(",", ":")).encode()) + "."
                     + b64url(json.dumps(claims, separators=(",", ":")).encode()))
    der_sig = pki.leaf_key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_ecdsa(der_sig)
    size = (pki.leaf_key.curve.key_size + 7) // 8
    size = 32 if size < 32 else size
    raw = r.to_bytes(size, "big")[-32:] + s.to_bytes(size, "big")[-32:]
    return (signing_input + "." + b64url(raw)).encode()


def decode_ecdsa(der: bytes) -> tuple[int, int]:
    parts = der_children(der)
    return int.from_bytes(parts[0][2:], "big"), int.from_bytes(parts[1][2:], "big")


# --- output -----------------------------------------------------------------

ROWS: list[dict] = []


def emit(rid: str, kind: str, data: bytes, roots: list[bytes] | None, bundle: str = BUNDLE):
    if kind == "receipt":
        options = {"bundleId": bundle, "roots": None if roots is None else [b64(r) for r in roots]}
    else:
        options = {"bundleId": "com.example.app", "acceptedEnvironments": ["Sandbox"], "appAppleId": None,
                   "roots": [b64(r) for r in roots]}
    ROWS.append({"id": "substrate/" + rid, "kind": kind, "options": json.dumps(options), "input": b64(data),
                 "base64": False, "guidHex": None, "op": 0})


def time_group():
    nb, na = LEAF
    moments = {
        "nb-minus-1ms": nb - 1, "nb": nb, "nb-plus-1ms": nb + 1, "mid": SIGNED,
        "na": na, "na-plus-1ms": na + 1, "na-plus-999ms": na + 999, "na-plus-1s": na + 1000,
    }
    rp, jp = Pki("receipt", tag="time"), Pki("jws", tag="time")
    for label, ms in moments.items():
        emit(f"time/receipt/{label}", "receipt", receipt(rp, iso_millis(ms)), rp.roots())
        emit(f"time/jws/{label}", "jws", jws(jp, ms), jp.roots())
    # whole-second spelling of notAfter, no fraction
    emit("time/receipt/na-no-fraction", "receipt", receipt(rp, "2025-12-31T23:59:59Z"), rp.roots())

    later = (at("2026-01-01T00:00:00Z"), at("2030-01-01T00:00:00Z"))
    cases = {
        "valid-now-not-at-signing": dict(leaf_win=later),
        "intermediate-expired-at-signing": dict(inter_win=(WIDE[0], at("2025-05-31T23:59:59Z"))),
        "intermediate-na-plus-1ms": dict(inter_win=(WIDE[0], SIGNED - 1000)),  # judged at SIGNED - 999
        "intermediate-na-exact": dict(inter_win=(WIDE[0], SIGNED)),
        "anchor-expired-at-signing": dict(root_win=(at("2010-01-01T00:00:00Z"), at("2011-01-01T00:00:00Z"))),
        "anchor-not-yet-valid-at-signing": dict(root_win=(at("2030-01-01T00:00:00Z"), at("2031-01-01T00:00:00Z"))),
    }
    for label, kw in cases.items():
        signed = SIGNED - 999 if label == "intermediate-na-plus-1ms" else SIGNED
        rp2, jp2 = Pki("receipt", tag=label, **kw), Pki("jws", tag=label, **kw)
        emit(f"time/receipt/{label}", "receipt", receipt(rp2, iso_millis(signed)), rp2.roots())
        emit(f"time/jws/{label}", "jws", jws(jp2, signed), jp2.roots())

    # Across 2050: notAfter is a GeneralizedTime.
    wide2 = (WIDE[0], at("2060-01-01T00:00:00Z"))
    g_na = at("2050-01-01T00:00:00Z")
    rp3 = Pki("receipt", root_win=wide2, inter_win=wide2, leaf_win=(LEAF[0], g_na), tag="2050")
    jp3 = Pki("jws", root_win=wide2, inter_win=wide2, leaf_win=(LEAF[0], g_na), tag="2050")
    for label, ms in {"gentime-na-minus-1ms": g_na - 1, "gentime-na": g_na, "gentime-na-plus-1ms": g_na + 1}.items():
        emit(f"time/receipt/{label}", "receipt", receipt(rp3, iso_millis(ms)), rp3.roots())
        emit(f"time/jws/{label}", "jws", jws(jp3, ms), jp3.roots())

    # Before 1970: negative Unix milliseconds (JWS only; a receipt date is a string).
    early = (at("1969-12-31T23:59:59Z"), at("2040-01-01T00:00:00Z"))
    jp4 = Pki("jws", root_win=(at("1960-01-01T00:00:00Z"), WIDE[1]), inter_win=(at("1960-01-01T00:00:00Z"), WIDE[1]),
              leaf_win=early, tag="1969")
    for label, ms in {"pre-1970-nb": -1000, "pre-1970-nb-plus-1ms": -999, "pre-1970-minus-1ms": -1,
                      "pre-1970-nb-minus-1ms": -1001}.items():
        emit(f"time/jws/{label}", "jws", jws(jp4, ms), jp4.roots())


def cms_group():
    p = Pki("receipt", tag="cms")
    roots = p.roots()
    content = receipt_payload("2025-06-01T00:00:00Z")
    good = signer_info(p.leaf, p.leaf_key, content)
    bad = signer_info(p.leaf, p.leaf_key, content, corrupt=True)
    stranger = rsa_key()
    stranger_cert = make_cert(name("Stranger"), stranger, name("Stranger"), stranger, *WIDE, [basic_constraints(False)])
    unknown_sid = signer_info(stranger_cert, stranger, content)
    ct = seq(oid(CONTENT_TYPE), set_of(oid(DATA)))
    st = seq(oid(SIGNING_TIME), set_of(x509_time(SIGNED)))
    md = seq(oid(MESSAGE_DIGEST), set_of(octets(hashlib.sha256(content).digest())))
    md_other = seq(oid(MESSAGE_DIGEST), set_of(octets(hashlib.sha256(b"other").digest())))
    cases = {
        "baseline-ber": receipt(p),
        "baseline-der": receipt(p, sd_ber=False),
        "no-signed-attributes": receipt(p, si_attrs=None),
        "second-signerinfo-bad-signature": receipt(p, infos=[good, bad]),
        "second-signerinfo-unknown-signer": receipt(p, infos=[good, unknown_sid]),
        "first-signerinfo-bad-second-good": receipt(p, infos=[bad, good]),
        "digestalgorithms-empty": receipt(p, sd_digest_algs=[]),
        "digestalgorithms-sha1-only": receipt(p, sd_digest_algs=[algid(SHA1)]),
        "digestalgorithms-sha256-sha512": receipt(p, sd_digest_algs=[algid(SHA256), algid(SHA512)]),
        "digest-params-absent": receipt(p, si_digest_null=False, sd_digest_algs=[algid(SHA256, False)]),
        "signer-digest-sha1": receipt(p, si_digest=SHA1, si_alg="sha1-rsa", sd_digest_algs=[algid(SHA1)]),
        "signature-alg-sha256withrsa-oid": receipt(p, si_sig_alg_oid=SHA256_RSA),
        "duplicate-contenttype": receipt(p, si_attrs=[ct, ct, st, md]),
        "duplicate-messagedigest": receipt(p, si_attrs=[ct, st, md, md]),
        "messagedigest-two-values": receipt(p, si_attrs=[ct, st, seq(oid(MESSAGE_DIGEST), set_of(
            octets(hashlib.sha256(content).digest()), octets(b"\x00" * 32)))]),
        "messagedigest-wrong": receipt(p, si_attrs=[ct, st, md_other]),
        "contenttype-missing": receipt(p, si_attrs=[st, md]),
        "contenttype-is-signeddata": receipt(p, si_attrs=[seq(oid(CONTENT_TYPE), set_of(oid(SIGNED_DATA))), st, md]),
        "attributes-unsorted-signed-as-sent": receipt(p, si_attrs=[st, md, ct], si_sort_attrs=False,
                                                      si_sign_sorted=False),
        "attributes-unsorted-signed-sorted": receipt(p, si_attrs=[st, md, ct], si_sort_attrs=False,
                                                     si_sign_sorted=True),
        "attributes-indefinite-length": receipt(p, si_attrs_indefinite=True),
        "unsigned-attributes": receipt(p, si_unsigned=seq(oid("1.2.3.4"), set_of(octets(b"x")))),
        "econtenttype-other": receipt(p, sd_e_content_type="1.2.3.4", si_e_content_type="1.2.3.4"),
        "content-constructed-octets": receipt(
            p, sd_content_field=indef(0x24, octets(content[:50]) + octets(content[50:120]) + octets(content[120:]))),
        "content-constructed-octets-definite": receipt(
            p, sd_content_field=tlv(0x24, octets(content[:50]) + octets(content[50:]))),
        "content-not-octets": receipt(p, sd_content_field=seq(octets(content))),
        "crls-garbage": receipt(p, sd_crls=seq(integer(1))),
        "crls-empty": receipt(p, sd_crls=b""),
        "signeddata-version-3": receipt(p, sd_version=3),
        "certificates-absent": receipt(p, certs=[]),
        "signer-not-first-in-bag": receipt(p, certs=[p.inter.der, p.leaf.der]),
    }
    for label, data in cases.items():
        emit(f"cms/{label}", "receipt", data, roots)

    # SubjectKeyIdentifier as the SignerIdentifier (CMS version 3 SignerInfo).
    ps = Pki("receipt", tag="ski", leaf_exts=[basic_constraints(False), ext(SKI, octets(b"\x11" * 20))])
    si = signer_info(ps.leaf, ps.leaf_key, content, sid=tlv(0x80, b"\x11" * 20), version=3)
    emit("cms/signer-identified-by-ski", "receipt", receipt(ps, infos=[si], sd_version=3), ps.roots())

    # Deep BER nesting inside an unsigned attribute value (unsigned, so the
    # signature still verifies).
    deep = b"\x30\x80" * 2000 + b"\x00\x00" * 2000
    emit("cms/unsigned-attribute-nesting-2000", "receipt",
         receipt(p, si_unsigned=seq(oid("1.2.3.4"), tlv(0x31, deep))), roots)
    deep = b"\x30\x80" * 100000 + b"\x00\x00" * 100000
    emit("cms/unsigned-attribute-nesting-100000", "receipt",
         receipt(p, si_unsigned=seq(oid("1.2.3.4"), tlv(0x31, deep))), roots)


def pkix_group():
    def both(label, receipt_only=False, **kw):
        rp = Pki("receipt", tag=label, **kw)
        emit(f"pkix/receipt/{label}", "receipt", receipt(rp), rp.roots())
        if not receipt_only:
            jp = Pki("jws", tag=label, **kw)
            emit(f"pkix/jws/{label}", "jws", jws(jp, SIGNED), jp.roots())

    unknown_critical = ext("1.2.3.4.5", null(), critical=True)
    both("intermediate-not-ca", inter_exts=[basic_constraints(False)])
    both("intermediate-no-basic-constraints", inter_exts=[])
    both("intermediate-version-1", inter_exts=[], inter_version=0, receipt_only=True)
    both("intermediate-keyusage-without-certsign", inter_exts=[basic_constraints(True), key_usage(0x80, 7)])
    both("intermediate-keyusage-certsign", inter_exts=[basic_constraints(True), key_usage(0x06, 1)])
    both("intermediate-unknown-critical-extension", inter_exts=[basic_constraints(True), unknown_critical])
    both("signer-unknown-critical-extension", leaf_exts=[basic_constraints(False), unknown_critical])
    both("signer-is-ca", leaf_exts=[basic_constraints(True)])
    both("signer-no-basic-constraints", leaf_exts=[])
    both("signer-eku-serverauth", leaf_exts=[basic_constraints(False),
                                             ext(EXT_KEY_USAGE, seq(oid("1.3.6.1.5.5.7.3.1")))])
    both("signer-keyusage-certsign-only", leaf_exts=[basic_constraints(False), key_usage(0x04, 2)])
    both("signer-aki-mismatch", leaf_exts=[basic_constraints(False), ext(AKI, seq(tlv(0x80, b"\x22" * 20)))])
    both("intermediate-pathlen-0", inter_exts=[basic_constraints(True, 0)])
    both("root-pathlen-0", root_exts=[basic_constraints(True, 0)])
    both("name-case-differs", leaf_issuer_name=name("SUBSTRATE CA name-case-differs"))
    both("name-printable-vs-utf8", leaf_issuer_name=name("Substrate CA name-printable-vs-utf8", "printable"))
    both("name-extra-whitespace", leaf_issuer_name=name("Substrate  CA name-extra-whitespace"))
    both("name-trailing-space", leaf_issuer_name=name("Substrate CA name-trailing-space "))
    both("serial-zero", leaf_serial=0, receipt_only=True)
    both("serial-negative", leaf_serial=-5, receipt_only=True)
    both("serial-21-octets", leaf_serial=1 << 164, receipt_only=True)
    both("chain-sha1", alg="sha1-rsa", receipt_only=True)
    both("chain-md5", alg="md5-rsa", receipt_only=True)
    both("signer-rsa-1024", leaf_key=rsa_key(1024), receipt_only=True)

    # Signer's marker extension marked critical.
    rp = Pki("receipt", tag="marker-critical", leaf_exts=[basic_constraints(False)])
    rp.leaf = make_cert(name("Substrate Signer marker-critical"), rp.leaf_key, name("Substrate CA marker-critical"),
                        rp.inter_key, *LEAF, [basic_constraints(False), ext(RECEIPT_MARKER, null(), critical=True)])
    emit("pkix/receipt/signer-marker-critical", "receipt", receipt(rp), rp.roots())

    # JWS leaf on P-384 (ES256 needs P-256).
    jp = Pki("jws", tag="p384", leaf_key=ec_key(ec.SECP384R1()))
    emit("pkix/jws/leaf-p384", "jws", jws(jp, SIGNED), jp.roots())

    # Trust anchors that are not self-signed roots.
    rp = Pki("receipt", tag="anchor-intermediate")
    emit("pkix/receipt/anchor-is-the-intermediate", "receipt", receipt(rp, certs=[rp.leaf.der]), [rp.inter.der])
    jp = Pki("jws", tag="anchor-intermediate")
    emit("pkix/jws/anchor-is-the-intermediate", "jws", jws(jp, SIGNED), [jp.inter.der])
    rp = Pki("receipt", tag="anchor-not-ca", root_exts=[basic_constraints(False)])
    emit("pkix/receipt/anchor-not-ca", "receipt", receipt(rp), rp.roots())
    jp = Pki("jws", tag="anchor-not-ca", root_exts=[basic_constraints(False)])
    emit("pkix/jws/anchor-not-ca", "jws", jws(jp, SIGNED), jp.roots())
    rp = Pki("receipt", tag="anchor-no-extensions", root_exts=[])
    emit("pkix/receipt/anchor-no-extensions", "receipt", receipt(rp), rp.roots())

    # Embedded self-signed impostor with the anchor's name but its own key.
    rp = Pki("receipt", tag="impostor")
    fake_key = rsa_key()
    root_name = name("Substrate Root impostor")
    fake_root = make_cert(root_name, fake_key, root_name, fake_key, *WIDE, [basic_constraints(True)])
    inter2 = make_cert(name("Substrate CA impostor"), rp.inter_key, root_name, fake_key, *WIDE,
                       [basic_constraints(True)])
    emit("pkix/receipt/chain-through-impostor-root", "receipt",
         receipt(rp, certs=[rp.leaf.der, inter2.der, fake_root.der]), rp.roots())
    # Both the real and the impostor intermediate: the builder must pick the one that validates.
    emit("pkix/receipt/impostor-intermediate-first", "receipt",
         receipt(rp, certs=[rp.leaf.der, inter2.der, rp.inter.der]), rp.roots())

    # Path length: n intermediates between the signer and the root.
    for n in (5, 6):
        root_key = rsa_key()
        root_name = name(f"Deep Root {n}")
        root = make_cert(root_name, root_key, root_name, root_key, *WIDE, [basic_constraints(True)])
        issuer_name, issuer_key, cas = root_name, root_key, []
        for i in range(n):
            k = rsa_key()
            nm = name(f"Deep CA {n}.{i}")
            cas.append(make_cert(nm, k, issuer_name, issuer_key, *WIDE, [basic_constraints(True)]))
            issuer_name, issuer_key = nm, k
        leaf_key = rsa_key()
        leaf = make_cert(name(f"Deep Signer {n}"), leaf_key, issuer_name, issuer_key, *LEAF,
                         [basic_constraints(False), ext(RECEIPT_MARKER, null())])
        content = receipt_payload("2025-06-01T00:00:00Z")
        info = signer_info(leaf, leaf_key, content)
        emit(f"pkix/receipt/intermediates-{n}", "receipt",
             signed_data(content, [leaf.der] + [c.der for c in cas], [info]), [root.der])

    # Two CAs issuing each other, no way up to the anchor.
    rp = Pki("receipt", tag="loop")
    ka, kb = rsa_key(), rsa_key()
    na_, nb_ = name("Loop A"), name("Loop B")
    ca_a = make_cert(na_, ka, nb_, kb, *WIDE, [basic_constraints(True)])
    ca_b = make_cert(nb_, kb, na_, ka, *WIDE, [basic_constraints(True)])
    leaf_key = rsa_key()
    leaf = make_cert(name("Loop Signer"), leaf_key, na_, ka, *LEAF, [basic_constraints(False), ext(RECEIPT_MARKER, null())])
    content = receipt_payload("2025-06-01T00:00:00Z")
    emit("pkix/receipt/issuer-loop", "receipt",
         signed_data(content, [leaf.der, ca_a.der, ca_b.der], [signer_info(leaf, leaf_key, content)]), rp.roots())


def flood_group():
    p = Pki("receipt", tag="flood")
    roots = p.roots()
    content = receipt_payload("2025-06-01T00:00:00Z")
    pad_key = rsa_key()
    pads = [make_cert(name(f"Pad {i}"), pad_key, name(f"Pad {i}"), pad_key, *WIDE, [basic_constraints(True)]).der
            for i in range(9)]
    emit("flood/certificates-10", "receipt", receipt(p, certs=[p.leaf.der, p.inter.der] + pads[:8]), roots)
    emit("flood/certificates-11", "receipt", receipt(p, certs=[p.leaf.der, p.inter.der] + pads[:9]), roots)
    good = signer_info(p.leaf, p.leaf_key, content)
    emit("flood/signerinfos-1000", "receipt", receipt(p, infos=[good] * 1000), roots)
    many = seq(oid("1.2.3.4"), set_of(*[octets(i.to_bytes(4, "big")) for i in range(10000)]))
    emit("flood/unsigned-attribute-values-10000", "receipt", receipt(p, si_unsigned=many), roots)
    extra = [seq(oid(f"1.2.3.4.{i}"), set_of(null())) for i in range(1000)]
    attrs = [seq(oid(CONTENT_TYPE), set_of(oid(DATA))), seq(oid(SIGNING_TIME), set_of(x509_time(SIGNED))),
             seq(oid(MESSAGE_DIGEST), set_of(octets(hashlib.sha256(content).digest())))] + extra
    emit("flood/signed-attributes-1003", "receipt", receipt(p, si_attrs=attrs), roots)
    emit("flood/digestalgorithms-1000", "receipt",
         receipt(p, sd_digest_algs=[algid(SHA256)] + [algid(f"1.2.3.{i}") for i in range(999)]), roots)


def parse_group(fixtures: Path):
    p = Pki("receipt", tag="parse")
    roots = p.roots()
    base = receipt(p)
    der = receipt(p, sd_ber=False)
    reg = json.loads((fixtures / "cases.json").read_text())["fixtures"]
    genuine = base64.b64decode((fixtures / reg["public-receipt-sandbox-g5"]["path"]).read_text())
    # The genuine receipt runs against the built-in Apple roots (roots null).
    for label, data, r, bundle in (("generated", base, roots, BUNDLE),
                                   ("genuine-g5", genuine, None, "dev.bonzer.weeka.app")):
        for k in range(1, 21):
            cut = len(data) * k // 21
            emit(f"parse/{label}/truncated-{k:02d}", "receipt", data[:cut], r, bundle)
        emit(f"parse/{label}/unchanged", "receipt", data, r, bundle)
        emit(f"parse/{label}/trailing-zero", "receipt", data + b"\x00", r, bundle)
        emit(f"parse/{label}/trailing-eoc", "receipt", data + b"\x00\x00", r, bundle)
        emit(f"parse/{label}/trailing-sequence", "receipt", data + seq(), r, bundle)
        if data[1] == 0x80:
            emit(f"parse/{label}/missing-final-eoc", "receipt", data[:-2], r, bundle)
            emit(f"parse/{label}/outer-huge-length", "receipt", b"\x30\x84\x7f\xff\xff\xff" + data[2:-2], r, bundle)
        else:
            body = data[read_header(data, 0)[1]:]
            emit(f"parse/{label}/outer-indefinite", "receipt", b"\x30\x80" + body + b"\x00\x00", r, bundle)
            emit(f"parse/{label}/outer-huge-length", "receipt", b"\x30\x84\x7f\xff\xff\xff" + body, r, bundle)
    # Non-minimal length encodings on the definite-length receipt.
    body = der[read_header(der, 0)[1]:]
    emit("parse/generated/outer-length-non-minimal", "receipt", b"\x30\x84" + len(body).to_bytes(4, "big") + body, roots)
    emit("parse/generated/outer-length-indefinite-over-der", "receipt", b"\x30\x80" + body + b"\x00\x00", roots)
    emit("parse/generated/der-baseline", "receipt", der, roots)
    emit("parse/nesting-100000-indefinite", "receipt", b"\x30\x80" * 100000 + b"\x00\x00" * 100000, roots)
    emit("parse/nesting-100000-unterminated", "receipt", b"\x30\x80" * 100000, roots)
    emit("parse/nesting-2000-definite", "receipt", _nest_definite(2000), roots)
    emit("parse/empty", "receipt", b"", roots)
    emit("parse/high-tag-number", "receipt", b"\x3f\x81\x80\x80\x80\x00\x00", roots)
    emit("parse/length-overflow-9-octets", "receipt", b"\x30\x89" + b"\xff" * 9, roots)


def _nest_definite(depth: int) -> bytes:
    out = b""
    for _ in range(depth):
        out = seq(out)
    return out


def main():
    fixtures = Path(sys.argv[1])
    time_group()
    cms_group()
    pkix_group()
    flood_group()
    parse_group(fixtures)
    for row in ROWS:
        print(json.dumps(row, separators=(",", ":")))
    print(f"{len(ROWS)} rows", file=sys.stderr)


if __name__ == "__main__":
    main()
