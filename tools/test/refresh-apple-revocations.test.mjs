// Tests for tools/refresh-apple-revocations.mjs. The lists are built here
// with openssl from a throwaway test CA: `asn1parse -genconf` writes the
// TBSCertList exactly as each test needs it (including shapes `openssl ca`
// cannot produce: a negative serial, a critical entry extension, an
// IssuingDistributionPoint), `dgst -sign` signs it, and a second genconf
// pass wraps it into the CertificateList.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  Refused,
  applyList,
  compareLists,
  integerHex,
  issuerCertificate,
  issuerId,
  main,
  normaliseHex,
  parseCertificate,
  parseCrl,
  verifyCrl,
  withJavaLines,
  withRustPin,
} from '../refresh-apple-revocations.mjs';
import { createHash } from 'node:crypto';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const dir = mkdtempSync(join(tmpdir(), 'aprv-revocation-test-'));
test.after(() => rmSync(dir, { recursive: true, force: true }));

const run = (...args) => execFileSync('openssl', args, { stdio: ['ignore', 'pipe', 'pipe'] });

// `marker`: carry Apple's WWDR marker extension (1.2.840.113635.100.6.2.1),
// which --check looks for on Apple's PKI page.
function makeCa(name, { marker = false } = {}) {
  const key = join(dir, `${name}.key`);
  run('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', key);
  writeFileSync(join(dir, `${name}.cnf`), [
    '[req]', 'distinguished_name=dn', 'x509_extensions=v3', 'prompt=no', 'string_mask=utf8only',
    '[dn]', 'CN=Test WWDR',
    '[v3]', 'basicConstraints=critical,CA:TRUE', 'keyUsage=critical,cRLSign,keyCertSign', 'subjectKeyIdentifier=hash',
    ...(marker ? ['1.2.840.113635.100.6.2.1=ASN1:UTF8String:marker'] : []),
  ].join('\n'));
  run('req', '-x509', '-new', '-key', key, '-config', join(dir, `${name}.cnf`), '-days', '3650', '-outform', 'DER', '-out', join(dir, `${name}.der`));
  const der = readFileSync(join(dir, `${name}.der`));
  return { key, der, ski: parseCertificate(der).ski.toString('hex') };
}

const ca = makeCa('ca');
// Same name, other key: a list it signs must not verify under `ca`.
const impostor = makeCa('impostor');

/**
 * genconf sections for a TBSCertList. `entries`: [{ serial (genconf
 * INTEGER text), reason (number), extra (genconf extension lines) }].
 */
function tbsSections({ version = true, nextUpdate = true, entries = [], crlNumber = '2135', aki = ca.ski, crlExts = [], extra = [] }) {
  const lines = ['[tbs]'];
  if (version) lines.push('version=INTEGER:1');
  lines.push('sig=SEQUENCE:sigalg', 'issuer=SEQUENCE:name', 'thisUpdate=UTCTIME:261105133646Z');
  if (nextUpdate) lines.push('nextUpdate=UTCTIME:261119133645Z');
  if (entries.length > 0) lines.push('revoked=SEQUENCE:revoked');
  const exts = [];
  if (aki) exts.push(['2.5.29.35', false, 'OCTWRAP,SEQUENCE:aki']);
  if (crlNumber !== null) exts.push(['2.5.29.20', false, `OCTWRAP,INTEGER:${crlNumber}`]);
  exts.push(...crlExts);
  if (exts.length > 0) lines.push('exts=EXPLICIT:0,SEQUENCE:crlexts');
  lines.push('[sigalg]', 'alg=OID:ecdsa-with-SHA256');
  lines.push('[name]', 'rdn=SET:rdn', '[rdn]', 'atv=SEQUENCE:atv', '[atv]', 'type=OID:commonName', 'value=UTF8:Test WWDR');
  if (aki) lines.push('[aki]', `kid=IMPLICIT:0,FORMAT:HEX,OCTETSTRING:${aki}`);
  lines.push('[crlexts]', ...exts.map((_, i) => `x${i}=SEQUENCE:crlext${i}`));
  exts.forEach(([oid, critical, value], i) => {
    lines.push(`[crlext${i}]`, `oid=OID:${oid}`, ...(critical ? ['critical=BOOLEAN:TRUE'] : []), `value=${value}`);
  });
  lines.push('[revoked]', ...entries.map((_, i) => `e${i}=SEQUENCE:entry${i}`));
  entries.forEach((e, i) => {
    const entryExts = [];
    if (e.reason !== undefined) entryExts.push(['2.5.29.21', false, `OCTWRAP,ENUMERATED:${e.reason}`]);
    entryExts.push(...(e.extra ?? []));
    lines.push(`[entry${i}]`, `serial=INTEGER:${e.serial}`, 'date=UTCTIME:260306235900Z');
    if (entryExts.length > 0) lines.push(`exts=SEQUENCE:entryexts${i}`);
    lines.push(`[entryexts${i}]`, ...entryExts.map((_, j) => `x${j}=SEQUENCE:entryext${i}_${j}`));
    entryExts.forEach(([oid, critical, value], j) => {
      lines.push(`[entryext${i}_${j}]`, `oid=OID:${oid}`, ...(critical ? ['critical=BOOLEAN:TRUE'] : []), `value=${value}`);
    });
  });
  lines.push(...extra);
  return lines.join('\n');
}

let counter = 0;
/** A DER CRL signed by `signer` (default: the test CA). */
function makeCrl(options = {}, signer = ca) {
  const n = counter++;
  const sections = tbsSections(options);
  const tbsCnf = join(dir, `tbs${n}.cnf`);
  const tbsDer = join(dir, `tbs${n}.der`);
  writeFileSync(tbsCnf, `asn1=SEQUENCE:tbs\n${sections}\n`);
  run('asn1parse', '-genconf', tbsCnf, '-out', tbsDer, '-noout');
  const sig = run('dgst', '-sha256', '-sign', signer.key, tbsDer);
  const crlCnf = join(dir, `crl${n}.cnf`);
  const crlDer = join(dir, `crl${n}.der`);
  writeFileSync(crlCnf, [
    'asn1=SEQUENCE:crl', '[crl]', 'tbs=SEQUENCE:tbs', 'alg=SEQUENCE:sigalg',
    `sig=FORMAT:HEX,BITSTRING:${sig.toString('hex')}`, sections, '',
  ].join('\n'));
  run('asn1parse', '-genconf', crlCnf, '-out', crlDer, '-noout');
  return readFileSync(crlDer);
}

const KEY_COMPROMISE = 1;
const HOLD = 6;

test('the test CA subject is the Name the lists carry, byte for byte', () => {
  const crl = parseCrl(makeCrl());
  assert.deepEqual(crl.issuer, parseCertificate(ca.der).subject);
});

test('a genuine list parses and verifies; serials and the CRL Number are normalised', () => {
  const der = makeCrl({
    entries: [
      { serial: '2', reason: KEY_COMPROMISE },
      { serial: '0x80', reason: KEY_COMPROMISE }, // DER 00 80
      { serial: '0', reason: KEY_COMPROMISE },
      { serial: '0x37D34791D02A56160329892A81C5A0EA' },
    ],
  });
  const crl = parseCrl(der);
  verifyCrl(der, crl, ca.der);
  assert.equal(crl.crlNumber, '0857'); // 2135, as G6's list carries it
  assert.equal(crl.thisUpdate, '2026-11-05T13:36:46Z');
  assert.equal(crl.nextUpdate, '2026-11-19T13:36:45Z');
  assert.deepEqual(crl.entries.map((e) => [e.serial, e.reason]), [
    ['02', 'keyCompromise'],
    ['80', 'keyCompromise'],
    ['00', 'keyCompromise'],
    ['37D34791D02A56160329892A81C5A0EA', null],
  ]);
  assert.equal(crl.entries[0].revocationDate, '2026-03-06T23:59:00Z');
});

test('serial normalisation follows §2', () => {
  assert.equal(integerHex(Buffer.from([0x02])), '02');
  assert.equal(integerHex(Buffer.from([0x00, 0x80])), '80');
  assert.equal(integerHex(Buffer.from([0x00])), '00');
  assert.equal(integerHex(Buffer.from([0x00, 0x00, 0x01, 0x00])), '0100');
  assert.equal(integerHex(Buffer.from([0x80])), null, 'negative');
  assert.equal(normaliseHex('2'), '02');
  assert.equal(normaliseHex('02'), '02');
  assert.equal(normaliseHex('0080'), '80');
  assert.equal(normaliseHex('abc'), '0ABC');
  assert.equal(normaliseHex('0'), '00');
});

test('a bad signature is refused', () => {
  const other = makeCrl({}, impostor);
  assert.throws(() => verifyCrl(other, parseCrl(other), ca.der), /signature does not verify|AuthorityKeyIdentifier/);
  // The impostor's list without an AKI reaches openssl and fails there.
  const noAki = makeCrl({ aki: null }, impostor);
  assert.throws(() => verifyCrl(noAki, parseCrl(noAki), ca.der), /signature does not verify/);
  // A flipped bit in the signature of the genuine list.
  const good = makeCrl({ entries: [{ serial: '2', reason: KEY_COMPROMISE }] });
  const bad = Buffer.from(good);
  bad[bad.length - 5] ^= 0x01;
  assert.throws(() => verifyCrl(bad, parseCrl(bad), ca.der), /signature does not verify/);
});

test('an AKI that names another key is refused', () => {
  const der = makeCrl({ aki: impostor.ski });
  assert.throws(() => verifyCrl(der, parseCrl(der), ca.der), /AuthorityKeyIdentifier does not match/);
});

test('lists outside the profile are refused', () => {
  const refused = (options, pattern) => {
    const der = makeCrl(options);
    assert.throws(() => parseCrl(der), (e) => e instanceof Refused && pattern.test(e.message));
  };
  refused({ crlExts: [['2.5.29.28', true, 'OCTWRAP,SEQUENCE:idp']], extra: ['[idp]', 'onlyUser=IMPLICIT:1,BOOLEAN:TRUE'] }, /IssuingDistributionPoint/);
  refused({ crlExts: [['2.5.29.27', true, 'OCTWRAP,INTEGER:5']] }, /delta/);
  refused({ crlExts: [['2.5.29.46', false, 'OCTWRAP,SEQUENCE:aki']] }, /FreshestCRL/);
  refused({ crlExts: [['1.2.3.4', true, 'OCTWRAP,INTEGER:1']] }, /critical extension 1\.2\.3\.4/);
  refused({ entries: [{ serial: '2', reason: KEY_COMPROMISE, extra: [['1.2.3.4', true, 'OCTWRAP,INTEGER:1']] }] }, /entry 02 has the critical extension/);
  refused({ entries: [{ serial: '2', extra: [['2.5.29.29', false, 'OCTWRAP,SEQUENCE:aki']] }] }, /indirect/);
  refused({ entries: [{ serial: '-5', reason: KEY_COMPROMISE }] }, /negative serial/);
  refused({ entries: [{ serial: '2' }, { serial: '0x02' }] }, /listed twice/);
  refused({ entries: [{ serial: '2', reason: 7 }] }, /unknown reason/);
  refused({ version: false }, /version 1/);
  refused({ nextUpdate: false }, /no nextUpdate/);
  assert.throws(() => parseCrl(Buffer.from('not a list')), Refused);
  assert.throws(() => parseCrl(Buffer.alloc(1024 * 1024 + 1)), /over the 1 MiB bound/);
});

test('a non-critical extension the profile does not read is accepted', () => {
  // WWDR G5's list carries expiredCertsOnCRL (2.5.29.60), not critical.
  const crl = parseCrl(makeCrl({ crlExts: [['2.5.29.60', false, 'OCTWRAP,GENTIME:20201216193856Z']] }));
  assert.equal(crl.crlNumber, '0857');
});

const ISSUER = 'aa'.repeat(32);
const fresh = () => ({ issuers: [{ id: ISSUER, name: 'Test WWDR', newest: null }], revoked: [] });
const listOf = (crlNumber, entries) => parseCrl(makeCrl({ crlNumber, entries }));

test('certificateHold and removeFromCRL entries are not added', () => {
  const doc = fresh();
  const r = applyList(doc, doc.issuers[0], listOf('10', [
    { serial: '2', reason: HOLD },
    { serial: '3', reason: 8 },
    { serial: '4', reason: KEY_COMPROMISE },
  ]));
  assert.deepEqual(doc.revoked.map((e) => e.serial), ['04']);
  assert.equal(r.changes.length, 1);
  assert.equal(r.notices.filter((n) => /not added/.test(n)).length, 2);
  assert.deepEqual(doc.revoked[0], {
    issuer: ISSUER, serial: '04', reason: 'keyCompromise', revocationDate: '2026-03-06T23:59:00Z', crlNumber: '0A',
  });
  assert.deepEqual(doc.issuers[0].newest, { crlNumber: '0A', thisUpdate: '2026-11-05T13:36:46Z' });
});

test('the file is append-only: an entry dropped from a newer list stays, reported once', () => {
  const doc = fresh();
  applyList(doc, doc.issuers[0], listOf('10', [{ serial: '2', reason: KEY_COMPROMISE }, { serial: '3', reason: KEY_COMPROMISE }]));
  const dropped = listOf('11', [{ serial: '3', reason: KEY_COMPROMISE }]);
  const r = applyList(doc, doc.issuers[0], dropped);
  assert.deepEqual(doc.revoked.map((e) => e.serial), ['02', '03']);
  assert.match(r.changes.join('\n'), /02 is no longer listed/);
  assert.deepEqual(doc.revoked[0].delisted, { crlNumber: '0B', thisUpdate: '2026-11-05T13:36:46Z' });
  // The next run sees the same list: nothing to report.
  assert.deepEqual(applyList(doc, doc.issuers[0], dropped).changes, []);
  // Listed again: reported, and the marker goes.
  const back = applyList(doc, doc.issuers[0], listOf('12', [{ serial: '2', reason: KEY_COMPROMISE }]));
  assert.match(back.changes.join('\n'), /02 is listed again/);
  assert.equal(doc.revoked[0].delisted, undefined);
});

test('a changed reason is reported and recorded; to certificateHold it is reported once', () => {
  const doc = fresh();
  applyList(doc, doc.issuers[0], listOf('10', [{ serial: '2', reason: 4 }]));
  const r = applyList(doc, doc.issuers[0], listOf('11', [{ serial: '2', reason: KEY_COMPROMISE }]));
  assert.match(r.changes.join('\n'), /changed reason from superseded to keyCompromise/);
  assert.equal(doc.revoked[0].reason, 'keyCompromise');
  // To certificateHold: the entry stays revoked with its reason, and the
  // change is recorded so the weekly --check does not fail on it again.
  const hold = applyList(doc, doc.issuers[0], listOf('12', [{ serial: '2', reason: HOLD }]));
  assert.match(hold.changes.join('\n'), /changed reason from keyCompromise to certificateHold; the entry stays revoked/);
  assert.equal(doc.revoked[0].reason, 'keyCompromise');
  assert.deepEqual(doc.revoked[0].listedAs, { reason: 'certificateHold', crlNumber: '0C', thisUpdate: '2026-11-05T13:36:46Z' });
  assert.deepEqual(applyList(doc, doc.issuers[0], listOf('13', [{ serial: '2', reason: HOLD }])).changes, []);
  // Back to the recorded reason: reported, and the marker goes.
  const back = applyList(doc, doc.issuers[0], listOf('14', [{ serial: '2', reason: KEY_COMPROMISE }]));
  assert.match(back.changes.join('\n'), /02 is listed as keyCompromise again/);
  assert.equal(doc.revoked[0].listedAs, undefined);
});

test('a list older than newest is refused; the same list is no change', () => {
  const doc = fresh();
  applyList(doc, doc.issuers[0], listOf('11', []));
  assert.throws(() => applyList(doc, doc.issuers[0], listOf('10', [])), /older than newest/);
  const same = applyList(doc, doc.issuers[0], listOf('11', []));
  assert.deepEqual(same, { changes: [], notices: [] });
  // Without a CRL Number on either side, thisUpdate decides.
  assert.equal(compareLists({ crlNumber: null, thisUpdate: '2025-03-10T00:00:00Z' }, { crlNumber: '05', thisUpdate: '2026-08-25T00:06:52Z' }), -1);
  assert.equal(compareLists({ crlNumber: '0100', thisUpdate: '2020-01-01T00:00:00Z' }, { crlNumber: 'FF', thisUpdate: '2026-01-01T00:00:00Z' }), 1);
});

test('the issuer id hashes the subject and key bytes as they appear in the certificate', () => {
  // Expected value computed independently: sha256 over bytes 184..303 and
  // 303..423 of the file (the subject and SPKI offsets openssl asn1parse
  // reports).
  const g6 = readFileSync(join(repoRoot, 'certs/revocation-issuers/AppleWWDRCAG6.cer'));
  assert.equal(issuerId(g6), 'ccb38ff9530770495de3a1cf2a9c868e7cbe76f871a46ee485699a7d32dd0bee');
});

test('certs/revocations.json: every issuer resolves to its certificate, entries are normalised', () => {
  const doc = JSON.parse(readFileSync(join(repoRoot, 'certs/revocations.json'), 'utf8'));
  assert.deepEqual(doc.issuers.map((i) => i.list), [
    'http://crl.apple.com/root.crl',
    'http://crl.apple.com/applerootcag3.crl',
    'http://crl.apple.com/wwdrg5.crl',
    'http://crl.apple.com/wwdrg6.crl',
  ]);
  for (const issuer of doc.issuers) assert.equal(issuerId(issuerCertificate(repoRoot, issuer)), issuer.id);
  const ids = new Set(doc.issuers.map((i) => i.id));
  for (const e of doc.revoked) {
    assert.ok(ids.has(e.issuer), `${e.serial}: unknown issuer`);
    assert.equal(normaliseHex(e.serial), e.serial);
    assert.ok(!['certificateHold', 'removeFromCRL'].includes(e.reason));
  }
});

// Write mode rewrites the core's pin and Java's constant with the file, or
// every verifier refuses the built-in list until someone edits both by
// hand. Rewriting them from the committed file changes nothing, which is
// what roots.rs's pin test and RevocationTest check in CI.
test('the pin in roots.rs and JSON_LINES in AppleRevocations.java follow the file', () => {
  const text = readFileSync(join(repoRoot, 'certs/revocations.json'), 'utf8');
  const rootsRs = readFileSync(join(repoRoot, 'rust/src/roots.rs'), 'utf8');
  const javaPath = 'java/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier/AppleRevocations.java';
  const java = readFileSync(join(repoRoot, javaPath), 'utf8');
  assert.equal(withRustPin(rootsRs, createHash('sha256').update(text).digest('hex')), rootsRs);
  assert.equal(withJavaLines(java, text), java);

  const changed = '{\n  "comment": "a \\"quoted\\" \\\\ text",\n  "revoked": []\n}\n';
  const lines = withJavaLines(java, changed);
  assert.ok(lines.includes([
    '    private static final String[] JSON_LINES = {',
    '        "{",',
    '        "  \\"comment\\": \\"a \\\\\\"quoted\\\\\\" \\\\\\\\ text\\",",',
    '        "  \\"revoked\\": []",',
    '        "}",',
    '    };',
  ].join('\n')), lines);
  const pin = 'ab'.repeat(32);
  assert.match(withRustPin(rootsRs, pin), new RegExp(`REVOCATIONS_JSON_SHA256: &str =\\s*"${pin}";`));
  assert.throws(() => withRustPin('no pin here', pin), /REVOCATIONS_JSON_SHA256 not found/);
  assert.throws(() => withJavaLines('no lines here', text), /JSON_LINES not found/);
});

// main --check, with `fetch` replaced: the exit status is what the weekly
// workflow runs on (1 = something to act on, 2 = a source could not be
// read), so a slip in it would leave every test above green and the watch
// wrong. Two issuers, each with its own WWDR-marked certificate; the PKI page
// links both, so the unknown-intermediate check passes.
const issuerA = makeCa('issuer-a', { marker: true });
const issuerB = makeCa('issuer-b', { marker: true });
const NEWER = '0857'; // the CRL Number 2135 the lists below carry
const PKI_URLS = {
  'https://www.apple.com/certificateauthority/': Buffer.from(
    '<a href="/certificateauthority/a.cer">A</a> <a href="/certificateauthority/b.cer">B</a>'),
  'https://www.apple.com/certificateauthority/a.cer': issuerA.der,
  'https://www.apple.com/certificateauthority/b.cer': issuerB.der,
};
const KNOWN = { serial: '2', reason: KEY_COMPROMISE };
const NEW = { serial: '3', reason: KEY_COMPROMISE };
const listFor = (issuer, entries) => makeCrl({ entries, aki: issuer.ski }, issuer);

/** A repository root holding certs/revocations.json for issuers A and B, each already recording entry 02 and a list older than 2135. */
function checkRoot() {
  const root = mkdtempSync(join(dir, 'root-'));
  mkdirSync(join(root, 'certs'));
  const issuers = [['a', issuerA], ['b', issuerB]].map(([key, ca_]) => {
    writeFileSync(join(root, 'certs', `${key}.cer`), ca_.der);
    return {
      id: issuerId(ca_.der), name: `Issuer ${key.toUpperCase()}`, certificate: `certs/${key}.cer`,
      list: `http://crl.test/${key}.crl`, newest: { crlNumber: '0856', thisUpdate: '2026-11-04T13:36:46Z' },
    };
  });
  const revoked = issuers.map((i) => ({
    issuer: i.id, serial: '02', reason: 'keyCompromise', revocationDate: '2026-03-06T23:59:00Z', crlNumber: '0856',
  }));
  writeFileSync(join(root, 'certs', 'revocations.json'), `${JSON.stringify({ issuers, revoked }, null, 2)}\n`);
  return root;
}

/** Replaces fetch: a route that is an Error is a network failure, a Buffer is the body, anything unrouted answers 404. */
function serve(t, routes) {
  t.mock.method(globalThis, 'fetch', async (url) => {
    const route = routes[String(url)];
    if (route instanceof Error) throw route;
    return route === undefined ? new Response('not found', { status: 404 }) : new Response(route);
  });
}

/** Runs main(--check) on `root`, returning its status and what it printed. */
async function check(t, root) {
  t.mock.method(console, 'log', () => {});
  t.mock.method(console, 'error', () => {});
  const code = await main(['--check'], { repoRoot: root });
  const text = (fn) => fn.mock.calls.map((c) => c.arguments.join(' ')).join('\n');
  return { code, out: text(console.log), err: text(console.error) };
}

test('main --check: a new entry exits 1', async (t) => {
  serve(t, {
    ...PKI_URLS,
    'http://crl.test/a.crl': listFor(issuerA, [KNOWN, NEW]),
    'http://crl.test/b.crl': listFor(issuerB, [KNOWN]),
  });
  const { code, out, err } = await check(t, checkRoot());
  assert.equal(code, 1);
  assert.match(out, /CHANGE: Issuer A: new entry 03/);
  assert.match(out, /Run node tools\/refresh-apple-revocations\.mjs/);
  assert.equal(err, '');
});

test('main --check: only a newer list exits 0', async (t) => {
  serve(t, {
    ...PKI_URLS,
    'http://crl.test/a.crl': listFor(issuerA, [KNOWN]),
    'http://crl.test/b.crl': listFor(issuerB, [KNOWN]),
  });
  const { code, out, err } = await check(t, checkRoot());
  assert.equal(code, 0);
  assert.match(out, new RegExp(`note: Issuer A: newer list, CRL Number ${NEWER}`));
  assert.match(out, /matches Apple's lists/);
  assert.doesNotMatch(out, /CHANGE/);
  assert.equal(err, '');
});

test('main --check: a network failure on the first issuer does not hide the next issuer\'s change', async (t) => {
  serve(t, {
    ...PKI_URLS,
    'https://crl.test/a.crl': new TypeError('fetch failed'),
    'http://crl.test/a.crl': new TypeError('fetch failed'),
    'http://crl.test/b.crl': listFor(issuerB, [KNOWN, NEW]),
  });
  const { code, out, err } = await check(t, checkRoot());
  assert.equal(code, 2, 'the network failure decides the status');
  assert.match(out, /CHANGE: Issuer B: new entry 03/, 'the change found after the failure is still printed');
  assert.doesNotMatch(out, /matches Apple's lists/);
  assert.match(err, /error: Issuer A: http:\/\/crl\.test\/a\.crl: fetch failed/);
});

test('main --check: an unreachable list with nothing else to report exits 2, not 0', async (t) => {
  serve(t, {
    ...PKI_URLS,
    'http://crl.test/a.crl': listFor(issuerA, [KNOWN]),
    // b.crl: HTTP 404 over both schemes
  });
  const { code, out, err } = await check(t, checkRoot());
  assert.equal(code, 2);
  assert.doesNotMatch(out, /matches Apple's lists/);
  assert.match(err, /error: Issuer B: .*HTTP 404/);
});
