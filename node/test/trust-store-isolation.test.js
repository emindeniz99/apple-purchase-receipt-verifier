// Trust reaches this library through exactly one door: `Config.roots`, set
// only by `createConfig({ roots })` or `defaultConfig()`. Not through Node's
// bundled Mozilla CA store, not through NODE_EXTRA_CA_CERTS, not through
// `tls.rootCertificates`, not through a platform verifier, not through a CA
// bundle on disk.
//
// Node is a language where that is easy to lose by accident. `node:crypto`'s
// primitives this package actually uses (`createPublicKey`, `verify`) have no
// trust store of their own — which is why this library can hold the property
// at all — but one `import { createSecureContext } from 'node:tls'`, or a
// dependency that reaches for `tls.rootCertificates` as a "sensible default",
// and pinned trust silently becomes "trust anything a public CA signed". And
// NODE_EXTRA_CA_CERTS makes that widening something a host operator can do
// from outside the process, with no code change at all.
//
// So the rule is asserted the same three ways the Go, Python, Swift, Rust,
// PHP and Ruby ports assert it:
//
//   * environmentally — a CA this *process* genuinely trusts buys an
//     attacker nothing. A child process is started with NODE_EXTRA_CA_CERTS
//     naming a bundle that holds the fixture roots; the child first proves
//     the planting took (a real TLS handshake against a server whose chain
//     ends at a planted CA is accepted with no `ca` option, and
//     `tls.getCACertificates('default')` lists the planted roots where that
//     API exists), and only then asks the library, which still refuses. A
//     child, because NODE_EXTRA_CA_CERTS is read once at startup.
//   * structurally — no module under src/ imports or names anything that
//     could reach a trust store or the network, and the web build imports
//     nothing Node-specific at all.
//   * positively — the anchor list that reaches the chain builder is, object
//     for object and in order, the list the caller handed in: nothing is
//     appended, dropped, reordered or substituted on the way.
//
// This file itself imports node:tls, node:fs and node:child_process on
// purpose: that is how it plants the trust store it then proves irrelevant.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { X509Certificate, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import tls from 'node:tls';
import * as node from '../dist/index.js';
import * as web from '../dist/web/index.js';
import { buildAndValidatePath, normalizeRoots, validatePair } from '../dist/chain.js';
import {
  buildAndValidatePath as webBuildAndValidatePath,
  normalizeRoots as webNormalizeRoots,
  validatePair as webValidatePair,
} from '../dist/web/chain.js';
import { parseCertificate } from '../dist/x509.js';

const read = (rel) => readFileSync(fileURLToPath(new URL(`../../${rel}`, import.meta.url)));
// The old, pre-0.7 receipt fixtures predate the intermediate-WWDR-marker
// hardening check and fail INVALID_CERTIFICATE_PURPOSE under verifyReceipt;
// the JWS fixtures are unaffected, so only the receipt ones move.
const fixture07 = (name) => read(`fixtures/generated-0.7/${name}`);
const fixture = (name) => read(`fixtures/generated/${name}`);
const fixtureText = (name) => fixture(name).toString('ascii').trim();
const publicReceipt = (name) =>
  read(`fixtures/public-receipts/${name}.b64`).toString('ascii').trim();

const SRC = fileURLToPath(new URL('../src/', import.meta.url));

const PEM_BEGIN_LINE = '-----BEGIN CERTIFICATE-----';

/** The DER a single web-build trust root normalized to, as base64. */
const derOfRoot = (root) => Buffer.from(webNormalizeRoots([root])[0].raw).toString('base64');

/** A DER certificate as a PEM block — the form a CA bundle and tls both take. */
function pem(der) {
  const body = Buffer.from(der)
    .toString('base64')
    .replace(/(.{64})/g, '$1\n')
    .trim();
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`;
}

// ---------------------------------------------------------------------------
// 1. The process trust store: planted, proved live, and still unreachable
// ---------------------------------------------------------------------------

// A minimal DER writer, enough for the throwaway TLS CA the child needs. The
// fixture roots cannot serve that purpose: the shared fixture PKI ships its
// certificates but not its private keys, so nothing here can issue a TLS leaf
// under `receipt-root.der`. The planted bundle therefore carries both — the
// fixture roots the library is asked about, and a CA generated here that a
// real handshake can prove the planting worked.

function tlv(tag, ...parts) {
  const contents = Buffer.concat(parts);
  const n = contents.length;
  const length =
    n < 0x80
      ? [n]
      : n < 0x100
        ? [0x81, n]
        : n < 0x10000
          ? [0x82, n >> 8, n & 0xff]
          : [0x83, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
  return Buffer.concat([Buffer.from([tag, ...length]), contents]);
}

const BOOLEAN = 0x01;
const INTEGER = 0x02;
const BIT_STRING = 0x03;
const OCTET_STRING = 0x04;
const NULL = 0x05;
const OID = 0x06;
const UTF8_STRING = 0x0c;
const UTC_TIME = 0x17;
const SEQUENCE = 0x30;
const SET = 0x31;
const CONTEXT_0 = 0xa0;
const CONTEXT_2 = 0x82;
const CONTEXT_3 = 0xa3;

const oid = (hex) => tlv(OID, Buffer.from(hex, 'hex'));
const OID_SHA256_RSA = '2a864886f70d01010b';
const OID_COMMON_NAME = '550403';
const OID_BASIC_CONSTRAINTS = '551d13';
const OID_KEY_USAGE = '551d0f';
const OID_SUBJECT_ALT_NAME = '551d11';
const OID_EXT_KEY_USAGE = '551d25';
const OID_SERVER_AUTH = '2b06010505070301';

const SHA256_RSA = tlv(SEQUENCE, oid(OID_SHA256_RSA), tlv(NULL));
const distinguishedName = (commonName) =>
  tlv(
    SEQUENCE,
    tlv(
      SET,
      tlv(SEQUENCE, oid(OID_COMMON_NAME), tlv(UTF8_STRING, Buffer.from(commonName, 'utf8'))),
    ),
  );
const VALIDITY = tlv(
  SEQUENCE,
  tlv(UTC_TIME, Buffer.from('200101000000Z', 'ascii')),
  tlv(UTC_TIME, Buffer.from('351231235959Z', 'ascii')),
);
const extension = (oidHex, critical, value) =>
  tlv(
    SEQUENCE,
    oid(oidHex),
    ...(critical ? [tlv(BOOLEAN, Buffer.from([0xff]))] : []),
    tlv(OCTET_STRING, value),
  );
// keyCertSign | cRLSign, and digitalSignature | keyEncipherment.
const CA_EXTENSIONS = [
  extension(OID_BASIC_CONSTRAINTS, true, tlv(SEQUENCE, tlv(BOOLEAN, Buffer.from([0xff])))),
  extension(OID_KEY_USAGE, true, tlv(BIT_STRING, Buffer.from([0x01, 0x06]))),
];
const LEAF_EXTENSIONS = [
  extension(OID_BASIC_CONSTRAINTS, true, tlv(SEQUENCE)),
  extension(OID_KEY_USAGE, true, tlv(BIT_STRING, Buffer.from([0x05, 0xa0]))),
  extension(OID_EXT_KEY_USAGE, false, tlv(SEQUENCE, oid(OID_SERVER_AUTH))),
  extension(
    OID_SUBJECT_ALT_NAME,
    false,
    tlv(SEQUENCE, tlv(CONTEXT_2, Buffer.from('localhost', 'ascii'))),
  ),
];

let nextSerial = 1;

/** A v3 certificate, signed for real: OpenSSL checks this one in a handshake. */
function certificate({ subject, issuer, subjectKey, issuerKey, extensions }) {
  const tbs = tlv(
    SEQUENCE,
    tlv(CONTEXT_0, tlv(INTEGER, Buffer.from([2]))),
    tlv(INTEGER, Buffer.from([nextSerial++])),
    SHA256_RSA,
    distinguishedName(issuer),
    VALIDITY,
    distinguishedName(subject),
    subjectKey.export({ type: 'spki', format: 'der' }),
    tlv(CONTEXT_3, tlv(SEQUENCE, ...extensions)),
  );
  return tlv(
    SEQUENCE,
    tbs,
    SHA256_RSA,
    tlv(BIT_STRING, Buffer.from([0]), cryptoSign('sha256', tbs, issuerKey)),
  );
}

/** A throwaway root + `localhost` server leaf, for the handshake premise. */
function ephemeralTlsPki() {
  const ca = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const leaf = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const caDer = certificate({
    subject: 'Planted Trust Anchor',
    issuer: 'Planted Trust Anchor',
    subjectKey: ca.publicKey,
    issuerKey: ca.privateKey,
    extensions: CA_EXTENSIONS,
  });
  const leafDer = certificate({
    subject: 'localhost',
    issuer: 'Planted Trust Anchor',
    subjectKey: leaf.publicKey,
    issuerKey: ca.privateKey,
    extensions: LEAF_EXTENSIONS,
  });
  return {
    caPem: pem(caDer),
    leafPem: pem(leafDer),
    leafKeyPem: leaf.privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

// The child. It runs with NODE_EXTRA_CA_CERTS already in place — the variable
// is read once, when the process starts, which is the whole reason this is a
// separate process and not a `process.env` assignment.
//
// Written to a temp directory rather than kept under test/ because everything
// under a `test/` directory is a test file to `node --test`, and this is a
// program that must only ever run with the planted environment around it.
//
// verifyReceipt/verifySignedData never throw for input the caller does not
// control (0.7 result objects, not exceptions) — only createConfig with an
// empty roots array does, so "refused" here means a failure result, not a
// catch.
const CHILD_SOURCE = String.raw`
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
// A namespace import, not named ones: node: builtins resolve their named
// exports at link time, and tls.getCACertificates does not exist on the Node 20
// floor this package claims — importing it by name would be a SyntaxError
// there rather than the guarded skip below.
import tls from 'node:tls';

const dist = process.env.APRV_DIST;
const dir = process.env.APRV_DIR;
const fixtures = process.env.APRV_FIXTURES;
const fixtures07 = process.env.APRV_FIXTURES_07;
const node = await import(dist + 'index.js');
const web = await import(dist + 'web/index.js');

const fixture = (n) => readFileSync(fixtures + n);
const fixture07 = (n) => readFileSync(fixtures07 + n);
const fixtureText = (n) => fixture(n).toString('ascii').trim();
const file = (n) => readFileSync(dir + '/' + n, 'utf8');

const checks = [];
const record = (name, body) => {
  try {
    const detail = body();
    checks.push({ name, ok: true, detail: detail ?? null });
  } catch (error) {
    checks.push({ name, ok: false, detail: String(error && error.stack ? error.stack : error) });
  }
};
const recordAsync = async (name, body) => {
  try {
    const detail = await body();
    checks.push({ name, ok: true, detail: detail ?? null });
  } catch (error) {
    checks.push({ name, ok: false, detail: String(error && error.stack ? error.stack : error) });
  }
};

const receiptRootPem = file('receipt-root.pem');
const receiptRootDer = fixture07('receipt-root.der');
const jwsRootDer = fixture('jws-root.der');
const receiptB64 = fixture07('receipt.der').toString('base64');
const transactionJws = fixtureText('transaction.jws');
const norm = (s) => s.replace(/\s+/g, '');

/** A failure result with the given reason, or throws describing why not. */
function refused(result, reason) {
  if (result.verified) {
    throw new Error('the material was ACCEPTED under anchors that did not certify it');
  }
  assert.equal(result.failure.reason, reason, result.failure.message);
  return result.failure.message;
}

// --- the premise ---------------------------------------------------------
// Without this the refusals below would prove nothing: they could be failing
// for any reason at all, including the planting never having happened.

record('premise: NODE_EXTRA_CA_CERTS names the planted bundle', () => {
  assert.equal(process.env.NODE_EXTRA_CA_CERTS, dir + '/planted-ca-bundle.pem');
  return process.env.NODE_EXTRA_CA_CERTS;
});

await recordAsync('premise: a TLS handshake trusts a planted CA with no ca option', async () => {
  const server = tls.createServer({ key: file('tls-leaf-key.pem'), cert: file('tls-leaf.pem') });
  server.on('secureConnection', (socket) => socket.end());
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const { port } = server.address();
    const authorized = await new Promise((resolve, reject) => {
      // No 'ca' option: this is the process default trust store answering,
      // and it says yes only because NODE_EXTRA_CA_CERTS put the root in it.
      const socket = tls.connect({ port, host: '127.0.0.1', servername: 'localhost' }, () => {
        const result = { authorized: socket.authorized, error: socket.authorizationError };
        socket.destroy();
        resolve(result);
      });
      socket.on('error', reject);
    });
    assert.equal(authorized.authorized, true, 'handshake not authorized: ' + authorized.error);
    return 'handshake authorized by the process default trust store';
  } finally {
    server.close();
  }
});

record('premise: the planted receipt root is in the default CA list', () => {
  if (typeof tls.getCACertificates !== 'function') {
    return 'skipped: tls.getCACertificates is not available on this Node';
  }
  const inDefault = tls.getCACertificates('default').some((c) => norm(c) === norm(receiptRootPem));
  const inBundled = tls.getCACertificates('bundled').some((c) => norm(c) === norm(receiptRootPem));
  assert.equal(inDefault, true, 'the planted root is not in the process default CA list');
  assert.equal(inBundled, false, 'the fixture root is somehow in the bundled Mozilla store');
  assert.equal(
    tls.rootCertificates.some((c) => norm(c) === norm(receiptRootPem)),
    false,
    'tls.rootCertificates changed meaning',
  );
  return 'in default, not in bundled';
});

// --- and the library still refuses ---------------------------------------

record('node: the planted root works when PASSED as an anchor', () => {
  const verifier = node.createVerifier(node.createConfig({ roots: [receiptRootDer] }));
  const result = verifier.verifyReceipt(receiptB64);
  assert.equal(result.verified, true, result.failure && result.failure.message);
  assert.equal(result.payload.bundleId, 'com.example.app');
  return result.payload.receiptType;
});

record('node: verifyReceipt refuses it under the bundled Apple roots', () =>
  refused(node.createVerifier(node.defaultConfig()).verifyReceipt(receiptB64), 'UNTRUSTED_CHAIN'),
);

record("node: verifyReceipt refuses it under Node's own bundled CA store", () =>
  refused(
    node.createVerifier(node.createConfig({ roots: [...tls.rootCertificates] })).verifyReceipt(receiptB64),
    'UNTRUSTED_CHAIN',
  ),
);

record('node: the planted JWS root works when PASSED as an anchor', () => {
  const verifier = node.createVerifier(node.createConfig({ roots: [jwsRootDer] }));
  const result = verifier.verifySignedData(transactionJws);
  assert.equal(result.verified, true, result.failure && result.failure.message);
  const payload = JSON.parse(result.payload.json);
  assert.equal(payload.bundleId, 'com.example.app');
  return payload.transactionId;
});

record('node: verifySignedData refuses it under the bundled Apple roots', () =>
  refused(node.createVerifier(node.defaultConfig()).verifySignedData(transactionJws), 'UNTRUSTED_CHAIN'),
);

// The web build runs in this same planted process. It cannot reach a trust
// store even in principle — it has no node: imports — but it is the build a
// WebCrypto-only runtime ships, so it is asserted rather than assumed.
await recordAsync('web: the planted root works when PASSED as an anchor', async () => {
  const verifier = web.createVerifier(await web.createConfig({ roots: [new Uint8Array(receiptRootDer)] }));
  const result = await verifier.verifyReceipt(receiptB64);
  assert.equal(result.verified, true, result.failure && result.failure.message);
  assert.equal(result.payload.bundleId, 'com.example.app');
  return result.payload.receiptType;
});

await recordAsync('web: verifyReceipt refuses it under the bundled Apple roots', async () => {
  const verifier = web.createVerifier(await web.defaultConfig());
  return refused(await verifier.verifyReceipt(receiptB64), 'UNTRUSTED_CHAIN');
});

await recordAsync("web: verifyReceipt refuses it under Node's own bundled CA store", async () => {
  const verifier = web.createVerifier(await web.createConfig({ roots: [...tls.rootCertificates] }));
  return refused(await verifier.verifyReceipt(receiptB64), 'UNTRUSTED_CHAIN');
});

await recordAsync('web: verifySignedData refuses it under the bundled Apple roots', async () => {
  const verifier = web.createVerifier(await web.defaultConfig());
  return refused(await verifier.verifySignedData(transactionJws), 'UNTRUSTED_CHAIN');
});

// An empty anchor set is a configuration error, never a fallback. The failure
// mode this rules out is "no anchors given, so use the system ones" — which,
// in a process whose system anchors have just been shown to be live and
// writable from outside, would be the whole property gone.
await recordAsync('an empty anchor set is a configuration error, not a fallback', async () => {
  assert.throws(() => node.createConfig({ roots: [] }), TypeError);
  assert.throws(() => node.createVerifier({ roots: [], clock: () => Date.now() }), TypeError);
  await assert.rejects(() => web.createConfig({ roots: [] }), TypeError);
  assert.throws(() => web.createVerifier({ roots: [], clock: () => Date.now() }), TypeError);
  return '4 entry points refuse an empty anchor set';
});

process.stdout.write(JSON.stringify(checks));
`;

test('a certificate authority this process genuinely trusts is still not an anchor', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'aprv-trust-'));
  const pki = ephemeralTlsPki();
  const receiptRootPem = pem(fixture07('receipt-root.der'));

  // One bundle, three roots: the two fixture roots the library is asked
  // about, and the CA whose leaf the handshake premise uses.
  writeFileSync(
    join(dir, 'planted-ca-bundle.pem'),
    receiptRootPem + pem(fixture('jws-root.der')) + pki.caPem,
  );
  writeFileSync(join(dir, 'receipt-root.pem'), receiptRootPem);
  writeFileSync(join(dir, 'tls-leaf.pem'), pki.leafPem + pki.caPem);
  writeFileSync(join(dir, 'tls-leaf-key.pem'), pki.leafKeyPem);
  writeFileSync(join(dir, 'child.mjs'), CHILD_SOURCE);

  const stdout = execFileSync(process.execPath, [join(dir, 'child.mjs')], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
    env: {
      ...process.env,
      NODE_EXTRA_CA_CERTS: join(dir, 'planted-ca-bundle.pem'),
      APRV_DIST: new URL('../dist/', import.meta.url).href,
      APRV_FIXTURES: fileURLToPath(new URL('../../fixtures/generated/', import.meta.url)),
      APRV_FIXTURES_07: fileURLToPath(new URL('../../fixtures/generated-0.7/', import.meta.url)),
      APRV_DIR: dir,
    },
  });

  const checks = JSON.parse(stdout);
  // Named, not just counted: a check that stopped running is a check that
  // stopped proving anything, and it must not disappear quietly.
  assert.deepEqual(
    checks.map((c) => c.name).toSorted(),
    [
      'an empty anchor set is a configuration error, not a fallback',
      'node: the planted JWS root works when PASSED as an anchor',
      'node: the planted root works when PASSED as an anchor',
      "node: verifyReceipt refuses it under Node's own bundled CA store",
      'node: verifyReceipt refuses it under the bundled Apple roots',
      'node: verifySignedData refuses it under the bundled Apple roots',
      'premise: NODE_EXTRA_CA_CERTS names the planted bundle',
      'premise: a TLS handshake trusts a planted CA with no ca option',
      'premise: the planted receipt root is in the default CA list',
      'web: the planted root works when PASSED as an anchor',
      "web: verifyReceipt refuses it under Node's own bundled CA store",
      'web: verifyReceipt refuses it under the bundled Apple roots',
      'web: verifySignedData refuses it under the bundled Apple roots',
    ],
    'the planted-trust child did not run the checks this test claims it runs',
  );
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const check of checks) {
    assert.ok(check.ok, `${check.name}\n${check.detail}`);
    // A check that could not establish its premise is not a passing check, and
    // it must not read like one: on the Node 20 floor tls.getCACertificates
    // does not exist, and only the handshake premise is available there.
    if (typeof check.detail === 'string' && check.detail.startsWith('skipped:')) {
      t.diagnostic(`${check.name}: ${check.detail}`);
    }
  }
});

// ---------------------------------------------------------------------------
// 2. The other direction: this host's real public roots confer no standing
// ---------------------------------------------------------------------------

test("Node's own bundled CA store, handed in as trustedRoots, verifies no Apple material", () => {
  const genuine = publicReceipt('receipt-sandbox-g5');
  const hostRoots = [...tls.rootCertificates];
  assert.ok(hostRoots.length > 1, 'no bundled CA store to read real public roots from');

  // The premise: genuinely Apple-signed material this library does accept,
  // so the refusal below is about the anchors and not about the receipt.
  const genuineResult = node.createVerifier(node.defaultConfig()).verifyReceipt(genuine);
  assert.equal(genuineResult.verified, true, genuineResult.failure?.message);
  assert.equal(genuineResult.payload.receiptType, 'ProductionSandbox');

  // And the conclusion: 140-odd certificate authorities that every TLS client
  // on this machine accepts, handed to the library as its entire anchor set,
  // verify nothing — because none of them issued anything here.
  const hostOnly = node
    .createVerifier(node.createConfig({ roots: hostRoots }))
    .verifyReceipt(genuine);
  assert.equal(hostOnly.verified, false);
  assert.equal(hostOnly.failure.reason, 'UNTRUSTED_CHAIN');

  // Nor does sitting next to Apple's roots in the caller's list buy a public
  // CA anything on material it did not certify: a fixture receipt (signed
  // under the fixture root, not Apple's) still fails with both present.
  const fixtureReceipt = fixture07('receipt.der').toString('base64');
  const appleRootsDer = node.defaultConfig().roots.map((r) => r.raw);
  const mixed = node
    .createVerifier(node.createConfig({ roots: [...hostRoots, ...appleRootsDer] }))
    .verifyReceipt(fixtureReceipt);
  assert.equal(mixed.verified, false);
  assert.equal(mixed.failure.reason, 'UNTRUSTED_CHAIN');
});

test('no bundled Apple anchor came from a host trust store', async () => {
  // If this package ever started folding ambient roots into its own set,
  // this is the first assertion that would change.
  const host = new Set(
    tls.rootCertificates.map((p) => {
      try {
        return new X509Certificate(p).raw.toString('base64');
      } catch {
        return '';
      }
    }),
  );
  const nodeRoots = node.defaultConfig().roots;
  const webRoots = (await web.defaultConfig()).roots;
  for (const anchor of nodeRoots) {
    assert.ok(
      !host.has(Buffer.from(anchor.raw).toString('base64')),
      'a bundled Apple root came from the host trust store',
    );
  }
  // And the DER the two builds bundle is the same DER, so neither can be
  // widened without the other.
  assert.deepEqual(
    webRoots.map((r) => Buffer.from(r.raw).toString('base64')),
    nodeRoots.map((r) => Buffer.from(r.raw).toString('base64')),
  );
});

test('an empty anchor set is a configuration error in every entry point', async () => {
  // There is no ambient anchor set to fall back to, and asking for one is
  // refused at the door rather than silently widened into "the system roots".
  const syncDoors = [
    () => node.createConfig({ roots: [] }),
    () => node.createVerifier({ roots: [], clock: () => Date.now() }),
    () => normalizeRoots([]),
    () => web.createVerifier({ roots: [], clock: () => Date.now() }),
    () => webNormalizeRoots([]),
  ];
  for (const call of syncDoors) {
    assert.throws(call, TypeError, 'an empty trustedRoots was not refused');
  }
  // createConfig in the web build is async (it checks the bundled roots'
  // fingerprint through crypto.subtle), so its refusal is a rejection even
  // when the throw that causes it is synchronous.
  await assert.rejects(() => web.createConfig({ roots: [] }), TypeError);
});

// ---------------------------------------------------------------------------
// 3. The positive half: exactly the caller's anchors, in order
// ---------------------------------------------------------------------------

/**
 * Anchor lists that record themselves at the moment the chain builder reads
 * them.
 *
 * `chain.ts`/`web/chain.ts` read anchors straight from `Config.roots` (no
 * `normalizeRoots` step in between when a `Config` is built by hand, as the
 * tests below do), and `Array.prototype.some`/iteration on a subclass
 * produces another instance of that subclass — so overriding the method by
 * which an array is read records exactly what reached the chain builder. No
 * module mocking and no loader hook: only the array semantics the library
 * already uses.
 *
 * Two classes rather than one, and each overrides exactly the one method its
 * build uses: the Node build's `issuedByAnyAnchor` reads anchors with
 * `anchors.some(...)`; the web build's reads them with `for...of`.
 */
let consulted = [];

/** A plain-array snapshot: every copying Array method would hand back a subclass. */
function record(anchors) {
  const snapshot = [];
  for (let index = 0; index < anchors.length; index++) {
    snapshot.push(anchors[index]);
  }
  consulted.push(snapshot);
}

function fill(Roots, items) {
  const array = new Roots(items.length);
  for (const [index, item] of items.entries()) {
    array[index] = item;
  }
  return array;
}

/** Records at `some` — how the Node build's chain.ts reads its anchors. */
class SomeRecordingRoots extends Array {
  some(callback, thisArg) {
    record(this);
    return super.some(callback, thisArg);
  }
}

/** Records at iteration — how the web build's chain.ts reads its anchors. */
class IterationRecordingRoots extends Array {
  [Symbol.iterator]() {
    record(this);
    return Array.prototype.values.call(this);
  }
}

/** Every anchor list the chain builder read while `run` executed. */
async function anchorsSeenBy(run) {
  consulted = [];
  await run();
  const seen = consulted;
  consulted = [];
  assert.ok(
    seen.length > 0,
    'the chain builder never read the array the caller passed — either it stopped reaching the ' +
      'chain builder, or something copied it on the way, which is exactly what appending an ' +
      'ambient trust store would look like',
  );
  return seen;
}

function assertAnchorsAre(expected, seen, identity) {
  for (const anchors of seen) {
    assert.equal(anchors.length, expected.length, 'the anchor set changed size in transit');
    for (const [index, anchor] of anchors.entries()) {
      assert.equal(
        identity(anchor),
        identity(expected[index]),
        `anchor ${index} is not the one the caller passed, or is out of order`,
      );
    }
  }
}

const same = (value) => value;
const derOf = (value) => Buffer.from(value.raw ?? value).toString('base64');

test('the receipt path builder sees exactly the anchors the caller passed', async () => {
  // Two anchors, the wrong one first: order, count and identity all have
  // something to lose. The receipt only chains to the second.
  const passed = [
    parseCertificate(fixture('jws-root.der')),
    parseCertificate(fixture07('receipt-root.der')),
  ];
  const receiptB64 = fixture07('receipt.der').toString('base64');
  const seen = await anchorsSeenBy(() => {
    const verifier = node.createVerifier({
      roots: fill(SomeRecordingRoots, passed),
      clock: () => Date.now(),
    });
    verifier.verifyReceipt(receiptB64);
  });
  assertAnchorsAre(passed, seen, same);
});

test('the JWS path builder sees exactly the anchors the caller passed', async () => {
  const passed = [
    parseCertificate(fixture07('receipt-root.der')),
    parseCertificate(fixture('jws-root.der')),
  ];
  const seen = await anchorsSeenBy(() => {
    const verifier = node.createVerifier({
      roots: fill(SomeRecordingRoots, passed),
      clock: () => Date.now(),
    });
    verifier.verifySignedData(fixtureText('transaction.jws'));
  });
  assertAnchorsAre(passed, seen, same);
});

test('the web chain builder sees exactly the anchors the caller passed', async () => {
  const passed = [
    parseCertificate(fixture('jws-root.der')),
    parseCertificate(fixture07('receipt-root.der')),
  ];
  const receiptB64 = fixture07('receipt.der').toString('base64');
  const seen = await anchorsSeenBy(async () => {
    const verifier = web.createVerifier({
      roots: fill(IterationRecordingRoots, passed),
      clock: () => Date.now(),
    });
    await verifier.verifyReceipt(receiptB64);
  });
  assertAnchorsAre(passed, seen, derOf);
});

test('normalizeRoots returns the caller list and nothing else, in both builds', () => {
  // The one seam every hand-built Config funnels its `roots` through when a
  // caller supplies DER/PEM rather than pre-parsed certificates. The spies
  // above watch what the chain builder READ; this watches what normalizeRoots
  // BUILT, so an ambient set appended after the caller's list would be caught
  // here even if it never reached the chain builder's own read.
  const passed = [fixture('jws-root.der'), fixture07('receipt-root.der')];

  const normalized = normalizeRoots(passed);
  assert.equal(normalized.length, passed.length, 'the Node anchor set changed size');
  for (const [index, anchor] of normalized.entries()) {
    assert.equal(
      Buffer.from(anchor.raw).toString('hex'),
      passed[index].toString('hex'),
      `anchor ${index} was substituted`,
    );
  }

  const normalizedWeb = webNormalizeRoots(passed.map((der) => new Uint8Array(der)));
  assert.equal(normalizedWeb.length, passed.length, 'the web anchor set changed size');
  assert.deepEqual(
    normalizedWeb.map((anchor) => Buffer.from(anchor.raw).toString('base64')),
    passed.map((der) => der.toString('base64')),
  );

  // And the premise the spies above rest on, asserted rather than assumed:
  // normalizeRoots reaches its result with `Array.prototype.map` and nothing
  // else, so a caller's own array subclass survives the call. An
  // implementation that copied the mapped list into a fresh array —
  // `[...normalizeRoots(x), ...somethingAmbient]` — would break this line,
  // which is the one thing the spies alone cannot see.
  const derItems = passed.map((der) => new Uint8Array(der));
  assert.ok(
    normalizeRoots(fill(SomeRecordingRoots, derItems)) instanceof SomeRecordingRoots,
    "the Node build's normalizeRoots no longer hands back the caller's own array subclass",
  );
  assert.ok(
    webNormalizeRoots(fill(IterationRecordingRoots, derItems)) instanceof IterationRecordingRoots,
    "the web build's normalizeRoots no longer hands back the caller's own array subclass",
  );
  consulted = [];
});

test('a PEM trust root is unwrapped in one pass, whatever the caller sends', () => {
  // `trustedRoots` is caller data, and both builds accept it as a PEM string.
  // The unwrapping used to be a lazy `[\s\S]*?` between the two marker
  // literals, which CodeQL flagged as a polynomial regular expression on
  // uncontrolled data: a string that opens a block and never closes it makes
  // that engine re-scan the tail from every candidate start. pem.ts's
  // `pemBody` is two `indexOf` calls, and these are the inputs that have to
  // keep behaving exactly as they did.
  const der = fixture('receipt-root.der');
  const expected = der.toString('base64');

  // The happy paths, unchanged: 64-column breaks, CRLF, blank lines and
  // indentation around the block, and junk on either side of it.
  const block = pem(der);
  assert.equal(derOfRoot(block), expected, 'the 64-column PEM stopped parsing');
  assert.equal(derOfRoot(block.replace(/\n/g, '\r\n')), expected, 'CRLF stopped parsing');
  assert.equal(derOfRoot(`\n\n   ${block}  \n\t\n`), expected, 'surrounding whitespace now bites');
  assert.equal(derOfRoot(`bundle header\n${block}trailer\n`), expected, 'junk around it now bites');

  // The adversarial half. The last entry is the one that actually made the
  // old regex crawl, and it is worth being precise about why, because the
  // obvious guess is wrong: a single unterminated block followed by a long
  // whitespace run costs V8 nothing (it finds the BEGIN literal once and
  // gives up). The quadratic case is an input where BEGIN matches over and
  // over with no END anywhere, so the lazy `[\s\S]*?` walks the whole
  // remaining tail again from each one. The indexOf scan does the same string
  // in under a millisecond, so the bound below is loose by orders of
  // magnitude and is not measuring runner speed.
  const SIZE = 400_000;
  const hostile = [
    `${PEM_BEGIN_LINE}\n${' '.repeat(SIZE)}`,
    `${PEM_BEGIN_LINE}\n${'\n'.repeat(SIZE)}`,
    `${PEM_BEGIN_LINE}\n${'A'.repeat(SIZE)}\n-----END CERTIFICATE`,
    `${'-'.repeat(SIZE)}${PEM_BEGIN_LINE}`,
    `${PEM_BEGIN_LINE}\n`.repeat(40_000),
  ];
  const started = process.hrtime.bigint();
  for (const input of hostile) {
    assert.throws(
      () => webNormalizeRoots([input]),
      TypeError,
      'an unterminated certificate block is no longer a TypeError',
    );
  }
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  assert.ok(elapsedMs < 2000, `rejecting ${hostile.length} hostile roots took ${elapsedMs}ms`);

  // And the ordinary refusals the same code path owes callers.
  for (const input of ['', 'not a certificate', PEM_BEGIN_LINE, '-----END CERTIFICATE-----']) {
    assert.throws(() => webNormalizeRoots([input]), TypeError);
  }
});

test('the chain primitives take their anchors only from their argument', () => {
  // The functions every verify path funnels through. Called directly with an
  // anchor set that certifies nothing, they refuse — there is no ambient set
  // behind the argument for them to fall back on.
  const stranger = parseCertificate(fixture('jws-root.der'));
  const signer = parseCertificate(fixture07('receipt-root.der'));
  const atMs = Date.parse('2024-08-06T12:00:00Z');
  assert.throws(
    () => buildAndValidatePath(signer, [signer], [stranger], atMs),
    (error) => error.reason === 'UNTRUSTED_CHAIN',
  );
  assert.throws(
    () => validatePair(signer, stranger, [stranger], atMs),
    (error) => error.reason === 'UNTRUSTED_CHAIN',
  );
});

test('the web chain primitives take their anchors only from their argument', async () => {
  const stranger = parseCertificate(fixture('jws-root.der'));
  const signer = parseCertificate(fixture07('receipt-root.der'));
  const atMs = Date.parse('2024-08-06T12:00:00Z');
  await assert.rejects(
    () => webBuildAndValidatePath(signer, [signer], [stranger], atMs),
    (error) => error.reason === 'UNTRUSTED_CHAIN',
  );
  await assert.rejects(
    () => webValidatePair(signer, stranger, [stranger], atMs),
    (error) => error.reason === 'UNTRUSTED_CHAIN',
  );
});

// ---------------------------------------------------------------------------
// 4. The structural half: a source scan over src/
// ---------------------------------------------------------------------------

/** Every .ts file under src/, deepest first. */
function sourceFiles(dir = SRC) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const entryPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...sourceFiles(entryPath));
    } else if (entry.name.endsWith('.ts')) {
      out.push(entryPath);
    }
  }
  return out.toSorted();
}

/**
 * A TypeScript source with comments removed, so the bans below land on code
 * and not on prose that legitimately names what the code avoids. This file's
 * own comments name every forbidden token.
 *
 * String and template literals are tracked, so a `//` inside one is not a
 * comment. Regular-expression literals are not tracked, which is safe here
 * and checked rather than assumed: `noRegexHidesAComment` below fails if any
 * source ever grows a regex containing `//` or `/*`.
 */
function stripComments(source) {
  let out = '';
  let index = 0;
  let quote = null;
  while (index < source.length) {
    const char = source[index];
    const next = source[index + 1];
    if (quote !== null) {
      if (char === '\\') {
        out += source.slice(index, index + 2);
        index += 2;
        continue;
      }
      if (char === quote) {
        quote = null;
      }
      out += char;
      index += 1;
      continue;
    }
    if (char === '/' && next === '/') {
      while (index < source.length && source[index] !== '\n') {
        index += 1;
      }
      continue;
    }
    if (char === '/' && next === '*') {
      index += 2;
      while (index < source.length && !(source[index] === '*' && source[index + 1] === '/')) {
        index += 1;
      }
      index += 2;
      continue;
    }
    if (char === "'" || char === '"' || char === '`') {
      quote = char;
    }
    out += char;
    index += 1;
  }
  return out;
}

const SOURCES = sourceFiles().map((entryPath) => ({
  path: entryPath,
  name: entryPath.slice(SRC.length),
  source: readFileSync(entryPath, 'utf8'),
  code: stripComments(readFileSync(entryPath, 'utf8')),
}));

test('the source scan is looking at the right tree', () => {
  assert.ok(
    SOURCES.length >= 25,
    `the source scan found only ${SOURCES.length} files under ${SRC}`,
  );
  assert.ok(
    SOURCES.some((f) => f.name.startsWith('web/')),
    'the web build was not scanned',
  );
});

// Every specifier a module of this package imports, per file.
const IMPORTS = SOURCES.flatMap((file) =>
  [...file.code.matchAll(/^\s*(?:import|export)[^'"]*from\s*'([^']+)'/gm)].map((m) => ({
    file,
    specifier: m[1],
  })),
);

test('the only non-relative imports in the whole package are node:crypto', () => {
  // An allowlist as well as a denylist: a denylist can only ban what we
  // thought of, and this catches the next `truststore`-shaped dependency
  // before it has a name. Zero runtime dependencies is a README claim, and
  // this is where it is mechanised. config.ts and receipt.ts use it for
  // createHash (fingerprint pinning, message digests); crypto.ts for the
  // signature primitives.
  const foreign = IMPORTS.filter(({ specifier }) => !specifier.startsWith('.')).map(
    ({ file, specifier }) => `${file.name} -> ${specifier}`,
  );
  assert.deepEqual(foreign.toSorted(), [
    'config.ts -> node:crypto',
    'crypto.ts -> node:crypto',
    'receipt.ts -> node:crypto',
  ]);
});

test('the node:crypto surface the package uses is exactly the reviewed one', () => {
  // None of these four can reach a trust store:
  //
  //   * `createHash` computes a digest over bytes it is handed.
  //   * `createPublicKey` builds a KeyObject from an SPKI this package
  //     already parsed itself (x509.ts), never from a certificate the
  //     platform resolved.
  //   * `verify` checks a signature against the key and data it is handed.
  //   * `constants` supplies the RSA-PSS padding/salt-length constants.
  //
  // `X509Certificate`, `createSecureContext`, or anything from node:tls
  // arriving here would fail this test before it could be used. Type-only
  // imports (erased at compile time, never reach dist/) are not counted.
  const imported = new Set();
  for (const { code } of SOURCES) {
    for (const match of code.matchAll(/import\s*\{([^}]*)\}\s*from\s*'node:crypto'/g)) {
      for (const part of match[1].split(',')) {
        const trimmed = part.trim();
        if (trimmed.length === 0 || trimmed.startsWith('type ')) {
          continue;
        }
        imported.add(trimmed.split(/\s+as\s+/)[0].trim());
      }
    }
  }
  assert.deepEqual([...imported].toSorted(), [
    'constants',
    'createHash',
    'createPublicKey',
    'verify',
  ]);
});

/** Every source module reachable from `entry` by following relative imports. */
function reachableFrom(entry) {
  const byName = new Map(SOURCES.map((file) => [file.name, file]));
  const seen = new Set();
  const queue = [entry];
  while (queue.length > 0) {
    const name = queue.pop();
    if (seen.has(name)) {
      continue;
    }
    seen.add(name);
    const file = byName.get(name);
    assert.ok(file !== undefined, `${name} is imported but not on disk`);
    for (const { specifier } of IMPORTS.filter((i) => i.file.name === name)) {
      if (specifier.startsWith('.')) {
        // './chain.js' in the source resolves to './chain.ts' on disk.
        queue.push(new URL(specifier, `file:///${name}`).pathname.slice(1).replace(/\.js$/, '.ts'));
      }
    }
  }
  return [...seen].map((name) => byName.get(name));
}

test('the web build imports nothing Node-specific, at source as well as in dist', () => {
  // web-portability.test.js makes this claim about the emitted dist; this is
  // the same claim one step earlier, over the modules actually reachable from
  // the web entry point — which includes the shared ones under src/, not just
  // the files under src/web/. A `node:crypto` import reaching any of them
  // fails here at review time rather than after a build.
  const reachable = reachableFrom('web/index.ts');
  assert.ok(reachable.length >= 20, `only ${reachable.length} modules reachable from web/index.ts`);
  for (const file of reachable) {
    for (const { specifier } of IMPORTS.filter((i) => i.file.name === file.name)) {
      assert.ok(
        specifier.startsWith('.'),
        `${file.name} is reachable from the web entry point and imports "${specifier}"`,
      );
    }
    assert.doesNotMatch(file.code, /\bBuffer\b/, `${file.name} names Buffer`);
    assert.doesNotMatch(file.code, /\bprocess\b/, `${file.name} names process`);
  }
  // And the Node-only modules (the ones importing node:crypto, plus the
  // top-level orchestrators that only the Node build wires up) are exactly
  // the ones the web build cannot see — it has its own web/ versions of each.
  const names = new Set(reachable.map((file) => file.name));
  for (const nodeOnly of [
    'chain.ts',
    'config.ts',
    'crypto.ts',
    'jws.ts',
    'receipt.ts',
    'verifier.ts',
  ]) {
    assert.ok(!names.has(nodeOnly), `${nodeOnly} is reachable from the web entry point`);
  }
});

test('no module names a trust store, a platform verifier or a network client', () => {
  // Matched as whole identifiers, so a word inside another name — or a
  // chain-building `path` variable, which chain.ts and receipt.ts both use
  // legitimately for a certificate path — is not a hit. Node built-in module
  // names are matched only as quoted specifiers (below), not as bare words,
  // for the same reason: "fs" and "path" are common identifiers that have
  // nothing to do with the modules of the same name, and the import allowlist
  // above already catches every static `from '<module>'`.
  const forbiddenWords = [
    // the trust-store and TLS-context APIs themselves.
    'rootCertificates',
    'getCACertificates',
    'setDefaultCACertificates',
    'createSecureContext',
    'SecureContext',
    'checkServerIdentity',
    'NODE_EXTRA_CA_CERTS',
    'SSL_CERT_FILE',
    'SSL_CERT_DIR',
    'REQUESTS_CA_BUNDLE',
    'NODE_TLS_REJECT_UNAUTHORIZED',
    // and the ways bytes could arrive from somewhere other than the caller.
    'fetch',
    'XMLHttpRequest',
    'WebSocket',
    'readFileSync',
    'readFile',
    'require',
    'process',
    'globalThis',
    'eval',
  ];
  const wordPatterns = forbiddenWords.map((token) => [token, new RegExp(`\\b${token}\\b`)]);
  // node: modules that reach a trust store, a peer, or a shell — matched only
  // as an actual module specifier (quoted, optionally 'node:'-prefixed).
  const forbiddenModules = [
    'tls',
    'https',
    'http',
    'http2',
    'net',
    'dgram',
    'dns',
    'child_process',
    'worker_threads',
    'vm',
    'fs',
    'os',
    'path',
    'module',
  ];
  const modulePatterns = forbiddenModules.map((name) => [
    name,
    new RegExp(`['"](?:node:)?${name}['"]`),
  ]);
  for (const file of SOURCES) {
    for (const [token, pattern] of [...wordPatterns, ...modulePatterns]) {
      assert.doesNotMatch(
        file.code,
        pattern,
        `${file.name} names "${token}" in code: anchors come from the caller's trustedRoots, ` +
          `and bytes come from the caller, never from the platform`,
      );
    }
  }
});

test('no string literal names a CA bundle, a trust store path or a URL', () => {
  // Prose legitimately names the Apple CA page this package does not fetch,
  // so this is the comment-stripped code only.
  const forbidden = [
    'http://',
    'https://',
    '/etc/ssl',
    '/etc/pki',
    'ca-certificates',
    'cacert.pem',
    'keychain',
    'Keychain',
    'System Roots',
  ];
  for (const file of SOURCES) {
    for (const literal of forbidden) {
      assert.ok(
        !file.code.includes(literal),
        `${file.name} has a code-level occurrence of "${literal}"`,
      );
    }
  }
});

test('no regular-expression literal hides a comment from the scanner', () => {
  // The one assumption stripComments makes, asserted rather than trusted: a
  // regex literal containing "//" or "/*" would be read as a comment and
  // could hide code from every scan above.
  for (const file of SOURCES) {
    for (const match of file.source.matchAll(/[=(,]\s*\/(?![/*])(?:\\.|\[[^\]]*\]|[^\\/\n])+\//g)) {
      assert.doesNotMatch(match[0], /\/\/|\/\*/, `${file.name} has a regex the scanner misreads`);
    }
  }
});

test('the package declares no runtime dependencies at all', () => {
  // The supply-chain half of the same rule: a dependency is how an ambient
  // trust store arrives without a single line of this package changing.
  const manifest = JSON.parse(read('node/package.json').toString('utf8'));
  assert.equal(manifest.dependencies, undefined);
  assert.equal(manifest.peerDependencies, undefined);
  assert.equal(manifest.optionalDependencies, undefined);
});
