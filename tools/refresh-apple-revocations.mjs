// Writes certs/revocations.json, the built-in revocation list compiled into
// the core and into Java (docs/design/revocation.md §5), from Apple's own
// certificate revocation lists.
//
// Usage: node tools/refresh-apple-revocations.mjs [--check]
//
// For every issuer in the file it downloads the issuer's list (HTTPS first,
// then the recorded HTTP URL: the signature, not the transport,
// authenticates the list), verifies its signature with `openssl crl
// -verify` against the issuer certificate from certs/, and refuses any list
// outside the profile of §4 or older than the issuer's `newest`. Then:
//
//   - an entry on the list and not in the file is appended, with the CRL
//     Number of the list it was first seen on. certificateHold and
//     removeFromCRL entries are reported and never added;
//   - an entry in the file is never removed (the file is append-only).
//     When it is no longer on its issuer's list it gains a `delisted`
//     member naming the first list without it, so the watch reports a
//     disappearance once and not every week after;
//   - a changed reason is reported and recorded;
//   - `newest` moves to the downloaded list.
//
// With --check nothing is written. It also reads Apple's PKI page and
// fails on a WWDR intermediate (marker 1.2.840.113635.100.6.2.1) that is
// neither in `issuers` nor in NOT_LIST_ISSUERS below. Exit status: 0 when
// the file is current or the only difference is a newer list (WWDR G6's is
// reissued daily); 1 on a new, vanished or reappearing entry, a changed
// reason, a refused list, or an unknown WWDR intermediate; 2 on a network
// failure or a bug in this script. Without --check it writes the file, its
// copy in rust/certs/, the file's SHA-256 pin in rust/src/roots.rs and the
// JSON_LINES constant in Java's AppleRevocations.java, which must all
// change together or the core and Java refuse the built-in list, and exits
// 0, or exits 2 on any failure, a refused list included.
//
// Parsing: `openssl asn1parse` reads every structure (tag, offsets,
// lengths); this script only slices the bytes at the offsets it reports and
// reads the few primitive values the profile needs (an INTEGER's sign and
// magnitude, a time, an OID). It carries no X.509 library and adds no npm
// dependency.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

export const MAX_LIST_BYTES = 1024 * 1024;
const PKI_PAGE = 'https://www.apple.com/certificateauthority/';
const WWDR_MARKER = '1.2.840.113635.100.6.2.1';

// WWDR intermediates on Apple's PKI page that sign no list a verifier can
// use, by issuer id. Both carry the WWDR marker; their lists,
// http://crl.apple.com/wwdrg3.crl and wwdrg4.crl, answered HTTP 404 on
// 2026-11-05 (docs/evidence/2026-11-05-apple-revocation-survey.md).
export const NOT_LIST_ISSUERS = new Map([
  ['e41db8db68b6f0cd82eb72630effff56c6ecbaba21de017fd557be9623f003bf', 'WWDR G3: no list published'],
  ['25dde22c2e2fe39de83ecb273bf2c249f4b59603152b1aa94d5c443435cc9e25', 'WWDR G4: no list published'],
]);

// RFC 5280 §5.3.1.
const REASONS = new Map([
  [0, 'unspecified'], [1, 'keyCompromise'], [2, 'cACompromise'], [3, 'affiliationChanged'],
  [4, 'superseded'], [5, 'cessationOfOperation'], [6, 'certificateHold'], [8, 'removeFromCRL'],
  [9, 'privilegeWithdrawn'], [10, 'aACompromise'],
]);
const NOT_ADDED = new Set(['certificateHold', 'removeFromCRL']);

const OID = {
  aki: '2.5.29.35', ski: '2.5.29.14', crlNumber: '2.5.29.20', deltaIndicator: '2.5.29.27',
  idp: '2.5.29.28', freshest: '2.5.29.46', reason: '2.5.29.21', invalidityDate: '2.5.29.24',
  certificateIssuer: '2.5.29.29',
};
// The extensions the profile interprets, and so the only ones that may be
// marked critical. Any other critical extension puts a list outside it.
const CRL_EXTENSIONS_READ = new Set([OID.aki, OID.crlNumber]);
const ENTRY_EXTENSIONS_READ = new Set([OID.reason, OID.invalidityDate]);

/** A list outside the profile, a bad signature, a downgrade. */
export class Refused extends Error {}

// ---------------------------------------------------------------- openssl

function openssl(args, input) {
  const r = spawnSync('openssl', args, { input, maxBuffer: 64 * 1024 * 1024 });
  if (r.error) throw new Error(`openssl ${args[0]}: ${r.error.message}`);
  return { status: r.status, stdout: r.stdout.toString('latin1'), stderr: r.stderr.toString('latin1') };
}

const LINE = /^\s*(\d+):d=(\d+)\s+hl=(\d+)\s+l=\s*(\d+|inf)\s+(cons|prim):/;

/**
 * The DER element tree of `der`, as `openssl asn1parse` reads it. Each node
 * carries its tag byte (read at the offset openssl gives), the offsets of
 * its whole encoding and of its content, and its children.
 */
export function asn1(der, what = 'input') {
  const r = openssl(['asn1parse', '-inform', 'DER'], der);
  if (r.status !== 0) throw new Refused(`${what}: not DER (${firstLine(r.stderr)})`);
  const nodes = [];
  for (const line of r.stdout.split('\n')) {
    if (line.trim() === '') continue;
    const m = LINE.exec(line);
    if (!m) throw new Refused(`${what}: unexpected asn1parse line ${JSON.stringify(line)}`);
    if (m[4] === 'inf') throw new Refused(`${what}: indefinite length is not DER`);
    const start = Number(m[1]);
    const hl = Number(m[3]);
    const end = start + hl + Number(m[4]);
    nodes.push({ depth: Number(m[2]), tag: der[start], start, content: start + hl, end, children: [] });
  }
  if (nodes.length === 0 || nodes[0].start !== 0 || nodes[0].end !== der.length) {
    throw new Refused(`${what}: not one DER element (trailing or missing bytes)`);
  }
  const stack = [];
  for (const node of nodes) {
    while (stack.length > 0 && stack.at(-1).depth >= node.depth) stack.pop();
    if (stack.length > 0) {
      const parent = stack.at(-1);
      if (node.depth !== parent.depth + 1 || node.end > parent.end) throw new Refused(`${what}: malformed nesting`);
      parent.children.push(node);
    } else if (node !== nodes[0]) {
      throw new Refused(`${what}: more than one top-level element`);
    }
    stack.push(node);
  }
  return nodes[0];
}

const firstLine = (text) => text.split('\n').find((l) => l.trim() !== '')?.trim() ?? 'no message';
const bytes = (der, node) => der.subarray(node.start, node.end);
const content = (der, node) => der.subarray(node.content, node.end);

function expect(node, tag, what) {
  if (!node || node.tag !== tag) {
    throw new Refused(`${what}: expected tag 0x${tag.toString(16)}, found ${node ? `0x${node.tag.toString(16)}` : 'nothing'}`);
  }
  return node;
}

// ---------------------------------------------------------------- values

/** Dotted form of an OBJECT IDENTIFIER's content octets. */
export function oidString(octets) {
  const arcs = [];
  let value = 0n;
  for (const b of octets) {
    value = (value << 7n) | BigInt(b & 0x7f);
    if ((b & 0x80) === 0) {
      arcs.push(value);
      value = 0n;
    }
  }
  if (arcs.length === 0 || (octets.at(-1) & 0x80) !== 0) throw new Refused('malformed OBJECT IDENTIFIER');
  const first = arcs[0] < 40n ? 0n : arcs[0] < 80n ? 1n : 2n;
  return [first, arcs[0] - first * 40n, ...arcs.slice(1)].join('.');
}

/**
 * §2: an INTEGER's content octets as uppercase hex, an even number of
 * digits, no leading 00 pair unless the value is zero. A negative value
 * returns null (never matched; refused here).
 */
export function integerHex(octets) {
  if (octets.length === 0) throw new Refused('empty INTEGER');
  if (octets[0] & 0x80) return null;
  let i = 0;
  while (i < octets.length - 1 && octets[i] === 0) i += 1;
  return Buffer.from(octets.subarray(i)).toString('hex').toUpperCase();
}

/** §2 normalisation of a hex string: either case, odd digit count. */
export function normaliseHex(hex) {
  if (typeof hex !== 'string' || !/^[0-9a-fA-F]+$/.test(hex)) throw new Error(`not hex: ${JSON.stringify(hex)}`);
  const even = hex.length % 2 ? `0${hex}` : hex;
  return integerHex(Buffer.from(even, 'hex')) ?? even.toUpperCase();
}

/** UTCTime or GeneralizedTime content as an ISO 8601 UTC string. */
export function timeString(der, node, what) {
  const text = content(der, node).toString('latin1');
  let m;
  if (node.tag === 0x17 && (m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text))) {
    const yy = Number(m[1]);
    return `${yy < 50 ? 2000 + yy : 1900 + yy}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z`;
  }
  if (node.tag === 0x18 && (m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text))) {
    return `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z`;
  }
  throw new Refused(`${what}: not a UTCTime or GeneralizedTime in the RFC 5280 form`);
}

/** The Extension SEQUENCEs under `seq`: [{oid, critical, value}]. */
function extensions(der, seq, what) {
  expect(seq, 0x30, what);
  const out = [];
  const seen = new Set();
  for (const ext of seq.children) {
    expect(ext, 0x30, what);
    const [id, second, third] = ext.children;
    const oid = oidString(content(der, expect(id, 0x06, what)));
    let critical = false;
    let valueNode = second;
    if (second?.tag === 0x01) {
      critical = content(der, second).some((b) => b !== 0);
      valueNode = third;
    }
    expect(valueNode, 0x04, `${what} ${oid}`);
    if (seen.has(oid)) throw new Refused(`${what}: extension ${oid} appears twice`);
    seen.add(oid);
    out.push({ oid, critical, value: Buffer.from(content(der, valueNode)) });
  }
  return out;
}

/** keyIdentifier of an AuthorityKeyIdentifier value, or null when absent. */
function akiKeyId(value) {
  const seq = expect(asn1(value, 'AuthorityKeyIdentifier'), 0x30, 'AuthorityKeyIdentifier');
  const keyId = seq.children.find((n) => n.tag === 0x80);
  return keyId ? Buffer.from(content(value, keyId)) : null;
}

// ---------------------------------------------------------------- certificates

/**
 * The parts of a certificate the tool needs. `id` is the §2 issuer id:
 * SHA-256 over the subject Name and the SubjectPublicKeyInfo, each taken
 * byte for byte from the certificate's TBSCertificate.
 */
export function parseCertificate(der, what = 'certificate') {
  const root = expect(asn1(der, what), 0x30, what);
  const tbs = expect(root.children[0], 0x30, `${what} TBSCertificate`);
  const fields = tbs.children[0]?.tag === 0xa0 ? tbs.children.slice(1) : tbs.children;
  const subject = expect(fields[4], 0x30, `${what} subject`);
  const spki = expect(fields[5], 0x30, `${what} subjectPublicKeyInfo`);
  const extNode = fields.slice(6).find((n) => n.tag === 0xa3);
  const exts = extNode ? extensions(der, expect(extNode.children[0], 0x30, what), `${what} extensions`) : [];
  const skiExt = exts.find((e) => e.oid === OID.ski);
  const subjectBytes = Buffer.from(bytes(der, subject));
  const spkiBytes = Buffer.from(bytes(der, spki));
  return {
    subject: subjectBytes,
    ski: skiExt ? Buffer.from(content(skiExt.value, expect(asn1(skiExt.value, 'SubjectKeyIdentifier'), 0x04, 'SKI'))) : null,
    extensions: exts,
    id: createHash('sha256').update(subjectBytes).update(spkiBytes).digest('hex'),
  };
}

export const issuerId = (der) => parseCertificate(der).id;

/** DER from a DER or PEM certificate file. */
export function certificateDer(data, what = 'certificate') {
  if (data.subarray(0, 11).toString('latin1') !== '-----BEGIN ') return data;
  const r = openssl(['x509', '-outform', 'DER'], data);
  if (r.status !== 0) throw new Refused(`${what}: not a certificate (${firstLine(r.stderr)})`);
  return Buffer.from(r.stdout, 'latin1');
}

// ---------------------------------------------------------------- lists

/**
 * Parses a CRL and refuses anything outside the §4 profile: version 2, a
 * nextUpdate, no IssuingDistributionPoint, DeltaCRLIndicator or
 * FreshestCRL, no indirect entry, no other critical extension, no
 * duplicate or negative serial, an AuthorityKeyIdentifier (when present)
 * with a keyIdentifier, a known reason code.
 */
export function parseCrl(der, what = 'list') {
  if (der.length > MAX_LIST_BYTES) throw new Refused(`${what}: ${der.length} bytes, over the 1 MiB bound`);
  const root = expect(asn1(der, what), 0x30, what);
  if (root.children.length !== 3) throw new Refused(`${what}: not a CertificateList`);
  const tbs = expect(root.children[0], 0x30, `${what} TBSCertList`);
  expect(root.children[1], 0x30, `${what} signatureAlgorithm`);
  expect(root.children[2], 0x03, `${what} signatureValue`);
  const f = [...tbs.children];
  if (f[0]?.tag !== 0x02) throw new Refused(`${what}: version 1 lists are outside the profile`);
  const version = integerHex(content(der, f.shift()));
  if (version !== '01') throw new Refused(`${what}: version field ${version}, not 2`);
  expect(f.shift(), 0x30, `${what} signature`);
  const issuer = expect(f.shift(), 0x30, `${what} issuer`);
  const thisNode = f.shift();
  const thisUpdate = timeString(der, thisNode ?? {}, `${what} thisUpdate`);
  if (!(f[0]?.tag === 0x17 || f[0]?.tag === 0x18)) throw new Refused(`${what}: no nextUpdate`);
  const nextUpdate = timeString(der, f.shift(), `${what} nextUpdate`);

  const entries = [];
  if (f[0]?.tag === 0x30) {
    const seen = new Set();
    for (const entry of f.shift().children) {
      expect(entry, 0x30, `${what} entry`);
      const [serialNode, dateNode, extNode, extra] = entry.children;
      if (extra) throw new Refused(`${what}: an entry has more than three fields`);
      const serial = integerHex(content(der, expect(serialNode, 0x02, `${what} entry serial`)));
      if (serial === null) throw new Refused(`${what}: a negative serial number`);
      if (seen.has(serial)) throw new Refused(`${what}: serial ${serial} is listed twice`);
      seen.add(serial);
      const revocationDate = timeString(der, dateNode ?? {}, `${what} entry ${serial} revocationDate`);
      let reason = null;
      for (const ext of extNode ? extensions(der, extNode, `${what} entry ${serial}`) : []) {
        if (ext.oid === OID.certificateIssuer) throw new Refused(`${what}: entry ${serial} is indirect (certificateIssuer)`);
        if (ext.critical && !ENTRY_EXTENSIONS_READ.has(ext.oid)) {
          throw new Refused(`${what}: entry ${serial} has the critical extension ${ext.oid}`);
        }
        if (ext.oid === OID.reason) {
          const node = expect(asn1(ext.value, 'reasonCode'), 0x0a, `${what} entry ${serial} reasonCode`);
          const code = content(ext.value, node);
          reason = code.length === 1 ? REASONS.get(code[0]) : undefined;
          if (reason === undefined) throw new Refused(`${what}: entry ${serial} has an unknown reason code`);
        }
      }
      entries.push({ serial, reason, revocationDate });
    }
  }

  let crlNumber = null;
  let aki = null;
  if (f[0]?.tag === 0xa0) {
    const wrapper = f.shift();
    if (wrapper.children.length !== 1) throw new Refused(`${what}: malformed crlExtensions`);
    for (const ext of extensions(der, wrapper.children[0], `${what} crlExtensions`)) {
      if (ext.oid === OID.idp) throw new Refused(`${what}: has an IssuingDistributionPoint`);
      if (ext.oid === OID.deltaIndicator) throw new Refused(`${what}: is a delta list (DeltaCRLIndicator)`);
      if (ext.oid === OID.freshest) throw new Refused(`${what}: has a FreshestCRL extension`);
      if (ext.critical && !CRL_EXTENSIONS_READ.has(ext.oid)) {
        throw new Refused(`${what}: has the critical extension ${ext.oid}`);
      }
      if (ext.oid === OID.crlNumber) {
        crlNumber = integerHex(content(ext.value, expect(asn1(ext.value, 'CRLNumber'), 0x02, `${what} CRL Number`)));
        if (crlNumber === null) throw new Refused(`${what}: a negative CRL Number`);
      }
      if (ext.oid === OID.aki) {
        aki = akiKeyId(ext.value);
        if (aki === null) throw new Refused(`${what}: AuthorityKeyIdentifier without a keyIdentifier`);
      }
    }
  }
  if (f.length > 0) throw new Refused(`${what}: unexpected fields after crlExtensions`);
  return { issuer: Buffer.from(bytes(der, issuer)), thisUpdate, nextUpdate, crlNumber, aki, entries };
}

const pem = (der) =>
  `-----BEGIN CERTIFICATE-----\n${der.toString('base64').replace(/.{1,64}/g, '$&\n')}-----END CERTIFICATE-----\n`;

/**
 * Refuses `crlDer` unless `issuerDer` signed it: its subject is
 * byte-identical to the list's issuer, its SubjectKeyIdentifier equals the
 * list's AuthorityKeyIdentifier when the list has one, and `openssl crl
 * -verify` accepts the signature with its key.
 */
export function verifyCrl(crlDer, crl, issuerDer, what = 'list') {
  const cert = parseCertificate(issuerDer, `${what} issuer certificate`);
  if (!cert.subject.equals(crl.issuer)) throw new Refused(`${what}: its issuer Name is not the issuer certificate's subject`);
  if (crl.aki && !(cert.ski && cert.ski.equals(crl.aki))) {
    throw new Refused(`${what}: its AuthorityKeyIdentifier does not match the issuer's SubjectKeyIdentifier`);
  }
  const dir = mkdtempSync(join(tmpdir(), 'aprv-crl-'));
  try {
    writeFileSync(join(dir, 'list.crl'), crlDer);
    writeFileSync(join(dir, 'issuer.pem'), pem(issuerDer));
    const r = openssl(['crl', '-inform', 'DER', '-in', join(dir, 'list.crl'), '-CAfile', join(dir, 'issuer.pem'), '-noout', '-verify']);
    if (r.status !== 0 || !/verify OK/.test(r.stdout + r.stderr)) {
      throw new Refused(`${what}: signature does not verify (${firstLine(r.stderr + r.stdout)})`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** -1, 0 or 1: is list `a` ({crlNumber, thisUpdate}) older than, as new as, or newer than `b` (§4)? */
export function compareLists(a, b) {
  if (a.crlNumber !== null && b.crlNumber !== null) {
    const x = BigInt(`0x${a.crlNumber}`);
    const y = BigInt(`0x${b.crlNumber}`);
    return x < y ? -1 : x > y ? 1 : 0;
  }
  return a.thisUpdate < b.thisUpdate ? -1 : a.thisUpdate > b.thisUpdate ? 1 : 0;
}

// ---------------------------------------------------------------- the file

/**
 * Applies a verified, parsed list to `doc` for issuer `issuer` (an entry of
 * doc.issuers). Returns { changes, notices }: a change is something --check
 * fails on, a notice is only reported. Mutates doc.
 */
export function applyList(doc, issuer, crl) {
  const changes = [];
  const notices = [];
  const label = issuer.name;
  if (issuer.newest) {
    const order = compareLists(crl, issuer.newest);
    if (order < 0) {
      throw new Refused(`${label}: the list downloaded (CRL Number ${crl.crlNumber ?? 'none'}, thisUpdate ${crl.thisUpdate}) is older than newest`);
    }
    if (order > 0) notices.push(`${label}: newer list, CRL Number ${crl.crlNumber ?? 'none'}, thisUpdate ${crl.thisUpdate}`);
  } else {
    notices.push(`${label}: first list recorded, CRL Number ${crl.crlNumber ?? 'none'}, thisUpdate ${crl.thisUpdate}`);
  }
  const listed = new Map(crl.entries.map((e) => [e.serial, e]));
  const recorded = doc.revoked.filter((r) => r.issuer === issuer.id);
  const recordedSerials = new Set(recorded.map((r) => r.serial));

  for (const r of recorded) {
    const now = listed.get(r.serial);
    if (!now) {
      if (!r.delisted) {
        changes.push(`${label}: ${r.serial} is no longer listed (kept: the file is append-only)`);
        r.delisted = { crlNumber: crl.crlNumber, thisUpdate: crl.thisUpdate };
      }
      continue;
    }
    if (r.delisted) {
      changes.push(`${label}: ${r.serial} is listed again`);
      delete r.delisted;
    }
    if (now.reason !== r.reason) {
      if (NOT_ADDED.has(now.reason)) {
        changes.push(`${label}: ${r.serial} changed reason from ${r.reason} to ${now.reason}; the entry stays revoked, decide by hand`);
      } else {
        changes.push(`${label}: ${r.serial} changed reason from ${r.reason} to ${now.reason}`);
        r.reason = now.reason;
      }
    }
  }
  for (const e of crl.entries) {
    if (recordedSerials.has(e.serial)) continue;
    if (NOT_ADDED.has(e.reason)) {
      notices.push(`${label}: ${e.serial} is listed with ${e.reason}, not added`);
      continue;
    }
    changes.push(`${label}: new entry ${e.serial} (${e.reason ?? 'no reason'}, ${e.revocationDate})`);
    doc.revoked.push({ issuer: issuer.id, serial: e.serial, reason: e.reason, revocationDate: e.revocationDate, crlNumber: crl.crlNumber });
  }
  issuer.newest = { crlNumber: crl.crlNumber, thisUpdate: crl.thisUpdate };
  return { changes, notices };
}

/**
 * The issuer certificate of `issuer`: its `certificate` file, or for a
 * root (certificate null) the top-level certs/*.cer whose issuer id is the
 * recorded one. Refuses a file whose id is not the recorded id.
 */
export function issuerCertificate(repoRoot, issuer) {
  if (issuer.certificate) {
    const der = certificateDer(readFileSync(join(repoRoot, issuer.certificate)), issuer.certificate);
    const id = issuerId(der);
    if (id !== issuer.id) throw new Refused(`${issuer.name}: ${issuer.certificate} has issuer id ${id}, not ${issuer.id}`);
    return der;
  }
  const dir = join(repoRoot, 'certs');
  for (const name of readdirSync(dir).filter((n) => n.endsWith('.cer')).sort()) {
    const der = certificateDer(readFileSync(join(dir, name)), name);
    if (issuerId(der) === issuer.id) return der;
  }
  throw new Refused(`${issuer.name}: no root in certs/ has issuer id ${issuer.id}`);
}

// ---------------------------------------------------------------- network

async function get(url) {
  let response;
  try {
    response = await fetch(url, {
      headers: { 'User-Agent': 'apple-purchase-receipt-verifier refresh-apple-revocations' },
      signal: AbortSignal.timeout(30_000),
    });
  } catch (error) {
    throw new Error(`${url}: ${error.cause?.message ?? error.message}`);
  }
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
  const body = Buffer.from(await response.arrayBuffer());
  return body;
}

/** The list at `url`, over HTTPS when Apple serves it there, else as recorded. */
async function download(url) {
  const https = url.replace(/^http:/, 'https:');
  if (https !== url) {
    try {
      return { bytes: await get(https), from: https };
    } catch {
      // Apple serves crl.apple.com over HTTP only (HTTPS answered 404 on
      // 2026-11-05); the signature check below authenticates either way.
    }
  }
  return { bytes: await get(url), from: url };
}

/** WWDR-marked intermediates linked from Apple's PKI page and not known here. */
async function unknownWwdrIntermediates(doc) {
  const html = (await get(PKI_PAGE)).toString('utf8');
  const urls = [...new Set([...html.matchAll(/href\s*=\s*["']([^"']+\.cer)["']/gi)].map((m) => new URL(m[1], PKI_PAGE).href))].sort();
  if (urls.length === 0) throw new Error(`${PKI_PAGE}: no .cer links found; the page layout changed`);
  const known = new Set(doc.issuers.map((i) => i.id));
  const found = [];
  let marked = 0;
  for (const url of urls) {
    const cert = parseCertificate(certificateDer(await get(url), url), url);
    if (!cert.extensions.some((e) => e.oid === WWDR_MARKER)) continue;
    marked += 1;
    if (!known.has(cert.id) && !NOT_LIST_ISSUERS.has(cert.id)) found.push(`PKI page: WWDR intermediate ${url} (issuer id ${cert.id}) is not in issuers`);
  }
  if (marked === 0) throw new Error(`${PKI_PAGE}: no WWDR-marked certificate found; the page layout changed`);
  return found;
}

// ---------------------------------------------------------------- main

// The pin of certs/revocations.json in rust/src/roots.rs, rewritten to
// `sha256`. Throws when the constant is not where it was.
export function withRustPin(rootsRs, sha256) {
  const pin = /(pub\(crate\) static REVOCATIONS_JSON_SHA256: &str =\s*")[0-9a-f]{64}(";)/;
  if (!pin.test(rootsRs)) throw new Error('rust/src/roots.rs: REVOCATIONS_JSON_SHA256 not found');
  return rootsRs.replace(pin, `$1${sha256}$2`);
}

// AppleRevocations.java with its JSON_LINES constant holding `text`, one
// Java string per line, as RevocationTest prints them. Throws when the
// constant is not where it was.
export function withJavaLines(java, text) {
  const block = /( {4}private static final String\[\] JSON_LINES = \{\n)[\s\S]*?(\n {4}\};)/;
  if (!block.test(java)) throw new Error('AppleRevocations.java: JSON_LINES not found');
  const lines = text.split('\n').filter((line) => line !== '')
    .map((line) => `        "${line.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}",`);
  return java.replace(block, (_whole, head, tail) => `${head}${lines.join('\n')}${tail}`);
}

export async function main(argv, { repoRoot = fileURLToPath(new URL('..', import.meta.url)) } = {}) {
  const { values } = parseArgs({ args: argv, options: { check: { type: 'boolean', default: false } } });
  const file = join(repoRoot, 'certs', 'revocations.json');
  const doc = JSON.parse(readFileSync(file, 'utf8'));
  const changes = [];
  const notices = [];
  for (const issuer of doc.issuers) {
    const issuerDer = issuerCertificate(repoRoot, issuer);
    const { bytes: der, from } = await download(issuer.list);
    try {
      const crl = parseCrl(der, from);
      verifyCrl(der, crl, issuerDer, from);
      const r = applyList(doc, issuer, crl);
      changes.push(...r.changes);
      notices.push(...r.notices);
    } catch (error) {
      if (!(error instanceof Refused) || !values.check) throw error;
      changes.push(`refused: ${error.message}`);
    }
  }
  if (values.check) changes.push(...(await unknownWwdrIntermediates(doc)));

  for (const line of notices) console.log(`note: ${line}`);
  for (const line of changes) console.log(`${values.check ? 'CHANGE' : 'changed'}: ${line}`);
  if (values.check) {
    if (changes.length === 0) console.log('certs/revocations.json matches Apple\'s lists');
    else console.log('Run node tools/refresh-apple-revocations.mjs, review the diff and open a pull request.');
    return changes.length === 0 ? 0 : 1;
  }
  // rust/certs/ is the copy the core compiles in; check-cert-copies.mjs
  // fails CI when the two differ. The core pins the copy's SHA-256 and Java
  // compiles the same text in: without both, every verifier refuses the
  // built-in list (the core answers INTERNAL_ERROR, Java's RevocationTest
  // fails).
  const text = `${JSON.stringify(doc, null, 2)}\n`;
  const rootsRs = join(repoRoot, 'rust', 'src', 'roots.rs');
  const java = join(repoRoot, 'java', 'src', 'main', 'java', 'io', 'github', 'emindeniz99',
    'applepurchasereceiptverifier', 'AppleRevocations.java');
  const pinned = withRustPin(readFileSync(rootsRs, 'utf8'), createHash('sha256').update(text).digest('hex'));
  const lines = withJavaLines(readFileSync(java, 'utf8'), text);
  writeFileSync(file, text);
  writeFileSync(join(repoRoot, 'rust', 'certs', 'revocations.json'), text);
  writeFileSync(rootsRs, pinned);
  writeFileSync(java, lines);
  console.log(`wrote certs/revocations.json and rust/certs/revocations.json (${doc.revoked.length} entries), `
    + 'the pin in rust/src/roots.rs and JSON_LINES in AppleRevocations.java');
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  // Node exits 1 on an uncaught error, which would read as "Apple changed
  // something". A failure to read Apple's sources, or a bug here, is not.
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (error) => {
      console.error(`refresh-apple-revocations: ${error instanceof Refused ? 'refused: ' : ''}${error.message}`);
      process.exit(2);
    },
  );
}
