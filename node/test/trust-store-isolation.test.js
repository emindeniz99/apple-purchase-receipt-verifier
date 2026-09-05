// Trust reaches this library through exactly one door: the `trustedRoots`
// option. Not through Node's bundled Mozilla CA store, not through
// NODE_EXTRA_CA_CERTS, not through `tls.rootCertificates`, not through a
// platform verifier, not through a CA bundle on disk.
//
// Node is a language where that is easy to lose by accident. `node:crypto`'s
// X509Certificate has no trust store of its own — which is why this library
// can hold the property at all — but one `import { createSecureContext } from
// 'node:tls'`, or a dependency that reaches for `tls.rootCertificates` as a
// "sensible default", and pinned trust silently becomes "trust anything a
// public CA signed". And NODE_EXTRA_CA_CERTS makes that widening something a
// host operator can do from outside the process, with no code change at all.
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
//     API exists), and only then asks the library, which still refuses.
//     A child, because NODE_EXTRA_CA_CERTS is read once at startup.
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
import { normalizeRoots as webNormalizeRoots } from '../dist/web/chain.js';

const BUNDLE = 'com.example.app';
const APPLE_RECEIPT_BUNDLE = 'dev.bonzer.weeka.app';

const read = (rel) => readFileSync(fileURLToPath(new URL(`../../${rel}`, import.meta.url)));
const fixture = (name) => read(`fixtures/generated/${name}`);
const fixtureText = (name) => fixture(name).toString('ascii').trim();
const publicReceipt = (name) =>
  read(`fixtures/public-receipts/${name}.b64`).toString('ascii').trim();

const SRC = fileURLToPath(new URL('../src/', import.meta.url));

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
const node = await import(dist + 'index.js');
const web = await import(dist + 'web/index.js');

const fixture = (n) => readFileSync(fixtures + n);
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
const receiptRootDer = fixture('receipt-root.der');
const jwsRootDer = fixture('jws-root.der');
const receiptDer = fixture('receipt.der');
const transactionJws = fixtureText('transaction.jws');
const norm = (s) => s.replace(/\s+/g, '');

function invalidChain(run) {
  return async () => {
    try {
      await run();
    } catch (error) {
      assert.equal(error.name, 'VerificationError', 'wrong error type: ' + error);
      assert.equal(error.reason, 'INVALID_CHAIN', error.message);
      return error.message;
    }
    throw new Error('the material was ACCEPTED under anchors that did not certify it');
  };
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
  const receipt = node.verifyReceiptCore(receiptDer, [receiptRootDer]);
  assert.equal(receipt.bundleId, 'com.example.app');
  return receipt.receiptType;
});

await recordAsync(
  'node: verifyReceiptCore refuses it under the bundled Apple roots',
  invalidChain(() => node.verifyReceiptCore(receiptDer, node.appleReceiptRoots())),
);
await recordAsync(
  'node: ReceiptVerifier refuses it under the bundled Apple roots',
  invalidChain(() =>
    new node.ReceiptVerifier({
      trustedRoots: node.appleReceiptRoots(),
      bundleId: 'com.example.app',
    }).verify(receiptDer),
  ),
);
await recordAsync(
  'node: verifyReceiptCore refuses it under Node’s own bundled CA store',
  invalidChain(() => node.verifyReceiptCore(receiptDer, [...tls.rootCertificates])),
);

record('node: the planted JWS root works when PASSED as an anchor', () => {
  const payload = new node.JwsVerifier({
    trustedRoots: [jwsRootDer],
    bundleId: 'com.example.app',
    acceptedEnvironments: ['Sandbox'],
  }).verifyTransaction(transactionJws);
  assert.equal(payload.bundleId, 'com.example.app');
  return payload.transactionId;
});

await recordAsync(
  'node: JwsVerifier refuses it under the bundled Apple roots',
  invalidChain(() =>
    new node.JwsVerifier({
      trustedRoots: node.appleJwsRoots(),
      bundleId: 'com.example.app',
      acceptedEnvironments: ['Sandbox'],
    }).verifyTransaction(transactionJws),
  ),
);

// The web build runs in this same planted process. It cannot reach a trust
// store even in principle — it has no node: imports — but it is the build a
// WebCrypto-only runtime ships, so it is asserted rather than assumed.
await recordAsync('web: the planted root works when PASSED as an anchor', async () => {
  const receipt = await web.verifyReceiptCore(new Uint8Array(receiptDer), [
    new Uint8Array(receiptRootDer),
  ]);
  assert.equal(receipt.bundleId, 'com.example.app');
  return receipt.receiptType;
});
await recordAsync(
  'web: verifyReceiptCore refuses it under the bundled Apple roots',
  invalidChain(() =>
    web.verifyReceiptCore(new Uint8Array(receiptDer), web.appleReceiptRoots()),
  ),
);
await recordAsync(
  'web: verifyReceiptCore refuses it under Node’s own bundled CA store',
  invalidChain(() => web.verifyReceiptCore(new Uint8Array(receiptDer), [...tls.rootCertificates])),
);
await recordAsync(
  'web: JwsVerifier refuses it under the bundled Apple roots',
  invalidChain(() =>
    new web.JwsVerifier({
      trustedRoots: web.appleJwsRoots(),
      bundleId: 'com.example.app',
      acceptedEnvironments: ['Sandbox'],
    }).verifyTransaction(transactionJws),
  ),
);

// An empty anchor set is a configuration error, never a fallback. The failure
// mode this rules out is "no anchors given, so use the system ones" — which,
// in a process whose system anchors have just been shown to be live and
// writable from outside, would be the whole property gone.
await recordAsync('an empty anchor set is a configuration error, not a fallback', async () => {
  const sync = [
    () => node.verifyReceiptCore(receiptDer, []),
    () => new node.ReceiptVerifier({ trustedRoots: [], bundleId: 'com.example.app' }),
    () =>
      new node.JwsVerifier({
        trustedRoots: [],
        bundleId: 'com.example.app',
        acceptedEnvironments: ['Sandbox'],
      }),
    () => new node.VerifyReceiptEndpoint({ trustedRoots: [], environment: 'Sandbox' }),
    () => new web.ReceiptVerifier({ trustedRoots: [], bundleId: 'com.example.app' }),
    () =>
      new web.JwsVerifier({
        trustedRoots: [],
        bundleId: 'com.example.app',
        acceptedEnvironments: ['Sandbox'],
      }),
  ];
  for (const call of sync) {
    assert.throws(call, TypeError, 'an empty trustedRoots was not refused');
  }
  // The web build's verify functions are async, so their refusal is a
  // rejection rather than a throw. It is still a TypeError and still
  // immediate: no anchors, no verdict.
  await assert.rejects(() => web.verifyReceiptCore(new Uint8Array(receiptDer), []), TypeError);
  return sync.length + 1 + ' entry points refuse an empty anchor set';
});

process.stdout.write(JSON.stringify(checks));
`;

test('a certificate authority this process genuinely trusts is still not an anchor', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'aprv-trust-'));
  const pki = ephemeralTlsPki();
  const receiptRootPem = pem(fixture('receipt-root.der'));

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
      'node: JwsVerifier refuses it under the bundled Apple roots',
      'node: ReceiptVerifier refuses it under the bundled Apple roots',
      'node: the planted JWS root works when PASSED as an anchor',
      'node: the planted root works when PASSED as an anchor',
      'node: verifyReceiptCore refuses it under Node’s own bundled CA store',
      'node: verifyReceiptCore refuses it under the bundled Apple roots',
      'premise: NODE_EXTRA_CA_CERTS names the planted bundle',
      'premise: a TLS handshake trusts a planted CA with no ca option',
      'premise: the planted receipt root is in the default CA list',
      'web: JwsVerifier refuses it under the bundled Apple roots',
      'web: the planted root works when PASSED as an anchor',
      'web: verifyReceiptCore refuses it under Node’s own bundled CA store',
      'web: verifyReceiptCore refuses it under the bundled Apple roots',
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
  assert.equal(
    new node.ReceiptVerifier({
      trustedRoots: node.appleReceiptRoots(),
      bundleId: APPLE_RECEIPT_BUNDLE,
    }).verify(genuine).receiptType,
    'ProductionSandbox',
  );

  // And the conclusion: 140-odd certificate authorities that every TLS client
  // on this machine accepts, handed to the library as its entire anchor set,
  // verify nothing — because none of them issued anything here.
  assert.throws(
    () =>
      new node.ReceiptVerifier({
        trustedRoots: hostRoots,
        bundleId: APPLE_RECEIPT_BUNDLE,
      }).verify(genuine),
    (error) => error.reason === 'INVALID_CHAIN',
  );

  // Nor does sitting next to Apple's roots in the caller's list buy a public
  // CA anything on material it did not certify.
  assert.throws(
    () =>
      node.verifyReceiptCore(fixture('receipt.der'), [...hostRoots, ...node.appleReceiptRoots()]),
    (error) => error.reason === 'INVALID_CHAIN',
  );
});

test('no bundled Apple anchor came from a host trust store', () => {
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
  for (const anchor of [...node.appleReceiptRoots(), ...node.appleJwsRoots()]) {
    assert.ok(
      !host.has(anchor.raw.toString('base64')),
      `${anchor.subject} came from the host trust store`,
    );
  }
  // And the DER the two builds bundle is the same DER, so neither can be
  // widened without the other.
  assert.deepEqual(
    web.appleReceiptRoots().map((d) => Buffer.from(d).toString('base64')),
    node.appleReceiptRoots().map((c) => c.raw.toString('base64')),
  );
});

test('an empty anchor set is a configuration error in every entry point', async () => {
  // There is no ambient anchor set to fall back to, and asking for one is
  // refused at the door rather than silently widened into "the system roots".
  const der = fixture('receipt.der');
  for (const call of [
    () => node.verifyReceiptCore(der, []),
    () => new node.ReceiptVerifier({ trustedRoots: [], bundleId: BUNDLE }),
    () => new node.JwsVerifier({ trustedRoots: [], bundleId: BUNDLE, acceptedEnvironments: [] }),
    () => new node.VerifyReceiptEndpoint({ trustedRoots: [], environment: 'Sandbox' }),
    () => normalizeRoots([]),
    () => new web.ReceiptVerifier({ trustedRoots: [], bundleId: BUNDLE }),
    () => new web.JwsVerifier({ trustedRoots: [], bundleId: BUNDLE, acceptedEnvironments: [] }),
  ]) {
    assert.throws(call, TypeError);
  }
  // Async in the web build, so its refusal is a rejection, not a throw.
  await assert.rejects(() => web.verifyReceiptCore(new Uint8Array(der), []), TypeError);
});

// ---------------------------------------------------------------------------
// 3. The positive half: exactly the caller's anchors, in order
// ---------------------------------------------------------------------------

/**
 * Anchor lists that record themselves at the moment the chain builder reads
 * them.
 *
 * `normalizeRoots` maps the caller's array, and `Array.prototype.map` on a
 * subclass produces another instance of that subclass — so the array the
 * chain builder is handed is still one of these, and overriding the method by
 * which it reads its anchors records exactly what reached it. No module
 * mocking and no loader hook: only the array semantics the library already
 * uses.
 *
 * Two classes rather than one, and each overrides exactly the one method its
 * build uses, because that is what makes the recording evidence. The Node
 * build reads anchors with `anchors.some(...)`; the web build's `anyIssued`
 * reads them with `for...of`. A class that recorded both would also record a
 * spread — and an implementation that spread the caller's list before
 * appending an ambient trust store to it would then look innocent, because
 * the snapshot taken at the spread is still exactly the caller's list. That
 * is not hypothetical: it is what this spy did in its first form, and what a
 * `[...normalizeRoots(x), ...tls.getCACertificates('default')]` regression looks
 * like from in here.
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

/** Records at iteration — how the web build's `anyIssued` reads its anchors. */
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
    new X509Certificate(fixture('jws-root.der')),
    new X509Certificate(fixture('receipt-root.der')),
  ];
  const seen = await anchorsSeenBy(() =>
    new node.ReceiptVerifier({
      trustedRoots: fill(SomeRecordingRoots, passed),
      bundleId: BUNDLE,
    }).verify(fixture('receipt.der')),
  );
  assertAnchorsAre(passed, seen, same);
});

test('the JWS path builder sees exactly the anchors the caller passed', async () => {
  const passed = [
    new X509Certificate(fixture('receipt-root.der')),
    new X509Certificate(fixture('jws-root.der')),
  ];
  const seen = await anchorsSeenBy(() =>
    new node.JwsVerifier({
      trustedRoots: fill(SomeRecordingRoots, passed),
      bundleId: BUNDLE,
      acceptedEnvironments: ['Sandbox'],
    }).verifyTransaction(fixtureText('transaction.jws')),
  );
  assertAnchorsAre(passed, seen, same);
});

test('the web chain builder sees exactly the anchors the caller passed', async () => {
  // The web build parses DER into its own certificate objects, so identity
  // here is the anchor's bytes rather than the object. The claim is the same:
  // nothing was added, dropped or reordered between caller and chain builder.
  const passed = [fixture('jws-root.der'), fixture('receipt-root.der')].map(
    (der) => new Uint8Array(der),
  );
  const seen = await anchorsSeenBy(() =>
    new web.ReceiptVerifier({
      trustedRoots: fill(IterationRecordingRoots, passed),
      bundleId: BUNDLE,
    }).verify(new Uint8Array(fixture('receipt.der'))),
  );
  assertAnchorsAre(passed, seen, derOf);
});

test('normalizeRoots returns the caller list and nothing else, in both builds', () => {
  // The one seam every verify path funnels through, asserted directly. The
  // spies above watch what the chain builder READ; this watches what the
  // library BUILT, so an ambient set appended after the caller's list is
  // caught even by an implementation that never lets the spy see the result.
  const passed = [fixture('jws-root.der'), fixture('receipt-root.der')];
  const asCertificates = passed.map((der) => new X509Certificate(der));

  const normalized = normalizeRoots(asCertificates);
  assert.equal(normalized.length, asCertificates.length, 'the Node anchor set changed size');
  for (const [index, anchor] of normalized.entries()) {
    assert.equal(anchor, asCertificates[index], `anchor ${index} was substituted`);
  }

  const normalizedWeb = webNormalizeRoots(passed.map((der) => new Uint8Array(der)));
  assert.equal(normalizedWeb.length, passed.length, 'the web anchor set changed size');
  assert.deepEqual(
    normalizedWeb.map((anchor) => Buffer.from(anchor.raw).toString('base64')),
    passed.map((der) => der.toString('base64')),
  );

  // And the premise the two spies above rest on, asserted rather than
  // assumed: normalizeRoots reaches its result with `Array.prototype.map` and
  // nothing else, so the array the chain builder receives is still the
  // caller's subclass and is still watched. An implementation that copied the
  // mapped list into a fresh array — `[...map(...), ...somethingAmbient]` —
  // would break this line, which is the one thing the spies alone cannot see.
  assert.ok(
    fill(SomeRecordingRoots, asCertificates) instanceof SomeRecordingRoots &&
      normalizeRoots(fill(SomeRecordingRoots, asCertificates)) instanceof SomeRecordingRoots,
    "the Node build no longer hands the chain builder the caller's own array",
  );
  assert.ok(
    webNormalizeRoots(
      fill(
        IterationRecordingRoots,
        passed.map((der) => new Uint8Array(der)),
      ),
    ) instanceof IterationRecordingRoots,
    "the web build no longer hands the chain builder the caller's own array",
  );
  consulted = [];
});

test('the chain primitives take their anchors only from their argument', () => {
  // The two functions every verify path funnels through. Called directly with
  // an anchor set that certifies nothing, they refuse — there is no ambient
  // set behind the argument for them to fall back on.
  const stranger = new X509Certificate(fixture('jws-root.der'));
  const signer = new X509Certificate(read('fixtures/generated/receipt-root.der'));
  assert.throws(
    () => buildAndValidatePath(signer, [signer], [stranger], new Date('2024-08-06T12:00:00Z')),
    (error) => error.reason === 'INVALID_CHAIN',
  );
  assert.throws(
    () => validatePair(signer, stranger, [stranger], new Date('2024-08-06T12:00:00Z')),
    (error) => error.reason === 'INVALID_CHAIN',
  );
});

// ---------------------------------------------------------------------------
// 4. The structural half: a source scan over src/
// ---------------------------------------------------------------------------

/** Every .ts file under src/, deepest first. */
function sourceFiles(dir = SRC) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...sourceFiles(path));
    } else if (entry.name.endsWith('.ts')) {
      out.push(path);
    }
  }
  return out.toSorted();
}

/**
 * A TypeScript source with comments removed, so the bans below land on code
 * and not on prose that legitimately names what the code avoids — `roots.ts`
 * cites Apple's `https://` CA page, and this file's own comments name every
 * forbidden token.
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

const SOURCES = sourceFiles().map((path) => ({
  path,
  name: path.slice(SRC.length),
  source: readFileSync(path, 'utf8'),
  code: stripComments(readFileSync(path, 'utf8')),
}));

test('the source scan is looking at the right tree', () => {
  assert.ok(
    SOURCES.length >= 15,
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

test('the only non-relative import in the whole package is node:crypto', () => {
  // An allowlist as well as a denylist: a denylist can only ban what we
  // thought of, and this catches the next `truststore`-shaped dependency
  // before it has a name. Zero runtime dependencies is a README claim, and
  // this is where it is mechanised.
  const foreign = IMPORTS.filter(({ specifier }) => !specifier.startsWith('.')).map(
    ({ file, specifier }) => `${file.name} -> ${specifier}`,
  );
  assert.deepEqual(foreign.toSorted(), [
    'chain.ts -> node:crypto',
    'jws.ts -> node:crypto',
    'receipt.ts -> node:crypto',
    'roots.ts -> node:crypto',
  ]);
});

test('the node:crypto surface the package uses is exactly the reviewed one', () => {
  // None of these four can reach a trust store, and that is the point of
  // pinning the list. In particular:
  //
  //   * `X509Certificate.prototype.verify(publicKey)` is a pure signature
  //     check against the key it is handed — it is NOT `SecTrustEvaluate`,
  //     it consults nothing, and it is how chain.ts checks each link. Its
  //     sibling `checkIssued(issuer)` is a name/AKI comparison, equally
  //     store-free. Both are allowed, and this assertion is what keeps them
  //     the only certificate APIs in play.
  //   * `crypto.verify(algorithm, data, key, signature)` likewise verifies
  //     against a key the caller supplies.
  //
  // `createSecureContext`, `Certificate`, or anything from node:tls arriving
  // here would fail this test before it could be used.
  const imported = new Set();
  for (const { code } of SOURCES) {
    for (const match of code.matchAll(/import\s*\{([^}]*)\}\s*from\s*'node:crypto'/g)) {
      for (const part of match[1].split(',')) {
        const name = part
          .trim()
          .split(/\s+as\s+/)[0]
          .trim();
        if (name.length > 0) {
          imported.add(name);
        }
      }
    }
  }
  assert.deepEqual([...imported].toSorted(), [
    'X509Certificate',
    'createHash',
    'timingSafeEqual',
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
  assert.ok(reachable.length >= 12, `only ${reachable.length} modules reachable from web/index.ts`);
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
  // And the four modules that do use node:crypto are exactly the ones the web
  // build cannot see.
  const names = new Set(reachable.map((file) => file.name));
  for (const nodeOnly of ['chain.ts', 'jws.ts', 'receipt.ts', 'roots.ts']) {
    assert.ok(!names.has(nodeOnly), `${nodeOnly} is reachable from the web entry point`);
  }
});

test('no module names a trust store, a platform verifier or a network client', () => {
  // Matched as whole identifiers, so a word inside another name is not a hit.
  // Each of these is a real way a Node library ends up trusting something its
  // caller never pinned.
  const forbidden = [
    // node: modules that reach a trust store, a peer, or a shell.
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
  const patterns = forbidden.map((token) => [token, new RegExp(`\\b${token}\\b`)]);
  for (const file of SOURCES) {
    for (const [token, pattern] of patterns) {
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
