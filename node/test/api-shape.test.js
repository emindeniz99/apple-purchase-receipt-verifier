// The two entry points are one product: the same pinned roots, the same
// vocabulary, and results a caller can read the same way.
// oxlint-disable no-await-in-loop -- two builds, one after the other, so a failure names its build
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { X509Certificate } from 'node:crypto';
import * as node from '../dist/index.js';
import * as web from '../dist/web/index.js';

const gen = (name) =>
  readFileSync(fileURLToPath(new URL(`../../fixtures/generated-0.7/${name}`, import.meta.url)));

test('both builds bundle the same three published Apple roots', async () => {
  const fromNode = node.defaultConfig().roots.map((r) => Buffer.from(r.raw));
  const fromWeb = (await web.defaultConfig()).roots.map((r) => Buffer.from(r.raw));
  assert.deepEqual(fromWeb, fromNode);
  const subjects = fromNode.map((der) => new X509Certificate(der).subject);
  assert.equal(subjects.length, 3);
  assert.ok(
    subjects.some((s) => /CN=Apple Root CA - G2/.test(s)),
    subjects,
  );
  assert.ok(
    subjects.some((s) => /CN=Apple Root CA - G3/.test(s)),
    subjects,
  );
  // The file Apple labels "Apple Inc. Root" has subject CN=Apple Root CA.
  assert.ok(
    subjects.some((s) => /CN=Apple Root CA$/m.test(s)),
    subjects,
  );
});

test('both builds expose the same Reason vocabulary and Environment set', () => {
  assert.deepEqual(web.Reason, node.Reason);
  assert.deepEqual(web.Environment, node.Environment);
  assert.deepEqual(web.AppleStatus, node.AppleStatus);
});

test('a result carries exactly one of payload and failure, in both builds', async () => {
  for (const [name, build] of [
    ['node', node],
    ['web', web],
  ]) {
    const verifier = build.createVerifier(
      await build.createConfig({ roots: [new Uint8Array(gen('receipt-root.der'))] }),
    );
    const results = {
      verified: await verifier.verifyReceipt(gen('receipt.der').toString('base64')),
      malformed: await verifier.verifyReceipt('AQIDBA=='),
      'not a string': await verifier.verifyReceipt(undefined),
      'untrusted chain': await verifier.verifyReceipt(
        gen('receipt-foreign.der').toString('base64'),
      ),
      'malformed jws': await verifier.verifySignedData('a.b'),
    };
    for (const [label, result] of Object.entries(results)) {
      const at = `${name}: ${label}`;
      assert.notEqual(result.payload === undefined, result.failure === undefined, at);
      assert.equal(result.verified, result.payload !== undefined, at);
    }
    assert.equal(results.verified.verified, true, name);
    assert.equal(results.malformed.failure.reason, 'MALFORMED', name);
    assert.equal(results['not a string'].failure.reason, 'MALFORMED', name);
    assert.equal(results['untrusted chain'].failure.reason, 'UNTRUSTED_CHAIN', name);
    assert.equal(results['malformed jws'].failure.reason, 'MALFORMED', name);
  }
});
