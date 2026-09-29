#!/usr/bin/env python3
"""Task 5: would three small, CMS-agnostic pre-checks make the OpenSSL CMS
build answer like Java on its remaining non-Java rows, and would they break
anything Java accepts? A Python MODEL of the checks, applied to the request
corpora and the native CMS rows. It does not change or build the Rust code.

    python3 prescan_model.py <corpora dir> <cms-native rows prefix> [fuzz rows prefix]

The checks (each only reads bytes; none re-encodes or rewrites input):
  T  (receipts) every UTCTime (tag 0x17) and GeneralizedTime (0x18) in the
     whole BER/DER tree has X.680 syntax: UTCTime YYMMDDhhmm[ss](Z|+hhmm|-hhmm),
     GeneralizedTime YYYYMMDDHH[MM[SS[.f+]]][Z|+hhmm|-hhmm], digits only
     where digits belong. Fails -> 9 (INVALID_RECEIPT_FORMAT), Java's answer
     for an unparseable time.
  A  (receipts) the first SignerInfo's signedAttrs [0] lists its SET OF
     elements in DER order (ascending, X.690 11.6), as RFC 5652 5.3
     requires. Length forms are NOT checked: Java accepts an indefinite-
     length signedAttrs (substrate/cms/attributes-indefinite-length), and
     so does OpenSSL; a definite-length requirement would reject it.
     Fails -> 5 (INVALID_SIGNATURE), Java's answer. It sits where the
     signature is checked (after the chain), so it only replaces a build
     answer of 0 or 5: modelled as "applies when the build said 0 or 5".
  U  (JWS) the protected header decodes (base64url) to valid UTF-8
     (RFC 7515 5.2 step 4, RFC 8259 8.1). Fails -> 1 (INVALID_JWS_FORMAT).
T and U run first (Java rejects these at parse time); A runs at the
signature step. Otherwise the build's code stands. "new_rejections" counts
rows that Java AND the build accept and a check would reject.
Endpoint rows are not modelled (their answer is a status document).
"""
import base64
import binascii
import json
import re
import sys

UTC = re.compile(rb"^\d{10}(\d{2})?(Z|[+-]\d{4})$")
GEN = re.compile(rb"^\d{10}(\d{2}(\d{2}([.,]\d+)?)?)?(Z|[+-]\d{4})?$")


class Bad(Exception):
    pass


def tlv(b, i, end):
    """One TLV at b[i:end]: (tag byte, constructed, header len, content len or None, next)."""
    if i + 2 > end:
        raise Bad("short")
    t = b[i]
    j = i + 1
    if t & 0x1F == 0x1F:
        while j < end and b[j] & 0x80:
            j += 1
        j += 1
    if j >= end:
        raise Bad("short")
    ln = b[j]
    j += 1
    if ln == 0x80:
        return t, bool(t & 0x20), j - i, None
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or j + n > end:
            raise Bad("length")
        ln = int.from_bytes(b[j:j + n], "big")
        j += n
    if j + ln > end:
        raise Bad("overrun")
    return t, bool(t & 0x20), j - i, ln


def walk(b, i, end, depth, visit):
    """Walks TLVs in b[i:end]; returns the offset after them (handles indefinite)."""
    while i < end:
        if depth > 200:
            raise Bad("deep")
        if b[i] == 0 and i + 1 < end and b[i + 1] == 0:
            return i + 2
        t, cons, hl, ln = tlv(b, i, end)
        cstart = i + hl
        if ln is None:
            if not cons:
                raise Bad("indefinite primitive")
            nxt = walk(b, cstart, end, depth + 1, visit)
            visit(t, cons, b, i, cstart, nxt - 2, depth)
            i = nxt
        else:
            if cons:
                walk(b, cstart, cstart + ln, depth + 1, visit)
            visit(t, cons, b, i, cstart, cstart + ln, depth)
            i = cstart + ln
    return i


def check_time(der):
    bad = []

    def v(t, cons, b, s, c, e, d):
        if t == 0x17 and not UTC.match(bytes(b[c:e])):
            bad.append(("UTCTime", s))
        if t == 0x18 and not GEN.match(bytes(b[c:e])):
            bad.append(("GeneralizedTime", s))
    try:
        walk(der, 0, len(der), 0, v)
    except Bad:
        return None  # not walkable: leave the answer to the build
    return bad


def children(b, c, e):
    out, i = [], c
    while i < e:
        t, cons, hl, ln = tlv(b, i, e)
        if ln is None:
            nxt = walk(b, i + hl, e, 1, lambda *a: None)
            out.append((t, i, i + hl, nxt - 2, nxt, True))
            i = nxt
        else:
            out.append((t, i, i + hl, i + hl + ln, i + hl + ln, False))
            i = i + hl + ln
    return out


def check_attrs(der):
    """True if the first SignerInfo's signedAttrs is DER-ordered (or absent)."""
    try:
        ci = children(der, 0, len(der))[0]
        sd_wrap = children(der, ci[2], ci[3])[1]            # [0] EXPLICIT
        sd = children(der, sd_wrap[2], sd_wrap[3])[0]       # SignedData SEQUENCE
        fields = children(der, sd[2], sd[3])
        sis = fields[-1]                                    # signerInfos SET
        si = children(der, sis[2], sis[3])[0]
        for f in children(der, si[2], si[3]):
            if f[0] == 0xA0:                                # signedAttrs [0] IMPLICIT
                elems = children(der, f[2], f[3])
                enc = [bytes(der[x[1]:x[4]]) for x in elems]
                width = max((len(x) for x in enc), default=0)
                keyed = [x.ljust(width, b"\0") for x in enc]
                return keyed == sorted(keyed)
        return True
    except (Bad, IndexError):
        return True  # not locatable: leave the answer to the build


def model(r, build_code):
    data = base64.b64decode(r["input"])
    if r["kind"] == "receipt":
        if r.get("base64"):
            try:
                data = base64.b64decode(data, validate=False)
            except (binascii.Error, ValueError):
                return None
        t = check_time(data)
        if t:
            return 9, "T", t[:2]
        if build_code in (0, 5) and not check_attrs(data):
            return 5, "A", None
        return None
    if r["kind"] == "jws":
        head = data.split(b".", 1)[0]
        try:
            raw = base64.urlsafe_b64decode(head + b"=" * (-len(head) % 4))
            raw.decode("utf-8")
        except (binascii.Error, ValueError):
            return 1, "U", None
    return None


def main():
    cdir, rows = sys.argv[1], sys.argv[2]
    corpora = ["cases", "substrate", "hostile", "algorithms"] + (["fuzz"] if len(sys.argv) > 3 else [])
    tot = {"rows": 0, "fired_T": 0, "fired_A": 0, "fired_U": 0, "java_equal_before": 0, "java_equal_after": 0, "new_rejections": 0}
    for c in corpora:
        prefix = sys.argv[3] if c == "fuzz" else rows
        reqs = [json.loads(l) for l in open(f"{cdir}/{c}.jsonl", encoding="utf-8")]
        java = {json.loads(l)["id"]: json.loads(l) for l in open(f"{cdir}/jvm25-{c}.jsonl", encoding="utf-8")}
        cand = {json.loads(l)["id"]: json.loads(l) for l in open(f"{prefix}-{c}.jsonl", encoding="utf-8")}
        for r in reqs:
            if r["kind"] == "endpoint":
                continue
            j, k = java[r["id"]].get("code"), cand[r["id"]].get("code")
            if not isinstance(k, int) or not isinstance(j, int) or k in (101,):
                continue
            tot["rows"] += 1
            m = model(r, k)
            after = m[0] if m else k
            tot["java_equal_before"] += j == k
            tot["java_equal_after"] += j == after
            if m:
                tot["fired_" + m[1]] += 1
                if j == 0 and k == 0 and after != 0:
                    tot["new_rejections"] += 1
                if j != k or j != after:
                    print(f"{c}: {r['id']} java {j} build {k} -> {after} ({m[1]}{' ' + str(m[2]) if m[2] else ''})")
    print("# totals (receipt + JWS rows the C ABI expresses):", json.dumps(tot))


if __name__ == "__main__":
    main()
