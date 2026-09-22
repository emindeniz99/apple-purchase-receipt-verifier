// decodeReceiptDataString decodes canonical standard base64 through
// Buffer.from before trying the full receipt-data decode. Buffer.from
// accepts anything, so the only thing keeping the verdicts unchanged is the
// gate in front of it. This compares the decoder against the full decode
// alone (receiptBase64DecodeStrict plus the error it maps to) on a seeded
// corpus built to sit on both sides of that gate: equal bytes when both
// accept, the same reason and message when both reject, and never one
// accepting what the other rejects.
import test from 'node:test';
import assert from 'node:assert/strict';
import { receiptBase64DecodeStrict } from '../dist/bytes.js';
import { decodeReceiptDataString } from '../dist/receipt.js';

/** The full decode with the fast path taken out: what the answers must equal. */
function fullDecode(text) {
  const decoded = receiptBase64DecodeStrict(text);
  if (decoded === null) {
    return { error: 'INVALID_RECEIPT_FORMAT: receipt-data is not valid base64' };
  }
  return { bytes: Buffer.from(decoded).toString('hex') };
}

function withFastPath(text) {
  try {
    return { bytes: decodeReceiptDataString(text).toString('hex') };
  } catch (error) {
    return { error: `${error.reason}: ${error.message.slice(error.reason.length + 2)}` };
  }
}

// Mirrors the gate in src/receipt.ts, only to count which branch each input
// took; the comparison itself does not depend on it.
const takesFastPath = (text) =>
  text.length !== 0 && text.length % 4 === 0 && /^[A-Za-z0-9+/]*={0,2}$/.test(text);

// mulberry32: small, seeded, and the same sequence on every run.
function rng(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const EXTRAS = ['-', '_', '=', ' ', '\n', '\r', '\t', '*', '.', 'é', '\u0000', 'Ａ'];

function corpus(count, seed) {
  const random = rng(seed);
  const int = (n) => Math.floor(random() * n);
  const pick = (list) => list[int(list.length)];
  const inputs = [];
  for (let i = 0; i < count; i++) {
    const bytes = Buffer.from(Array.from({ length: int(48) }, () => int(256)));
    let text = bytes.toString('base64');
    switch (int(12)) {
      case 0:
      case 1:
      case 2:
        break; // canonical, the fast path's whole domain
      case 3: // flip the unused low bits of the last data character
        text = text.replace(/[A-Za-z0-9+/](?==*$)/, () => pick([...ALPHABET]));
        break;
      case 4:
        text = text.replace(/=+$/, '');
        break;
      case 5:
        text += '='.repeat(1 + int(3));
        break;
      case 6:
        text = bytes.toString('base64url');
        break;
      case 7: {
        const at = int(text.length + 1);
        text = text.slice(0, at) + pick(EXTRAS) + text.slice(at);
        break;
      }
      case 8:
        text = text.slice(0, Math.max(0, text.length - 1 - int(3)));
        break;
      case 9: // random characters from both alphabets, whitespace and padding
        text = Array.from({ length: int(24) }, () =>
          random() < 0.8 ? ALPHABET[int(64)] : pick(EXTRAS),
        ).join('');
        break;
      case 10: // line-wrapped the way Foundation does it
        text = text.replace(/(.{4})/g, (run) => (random() < 0.3 ? `${run}\r\n` : run));
        break;
      default: {
        const at = int(text.length);
        text = text.slice(0, at) + pick([...ALPHABET, ...EXTRAS]) + text.slice(at + 1);
      }
    }
    inputs.push(text);
  }
  return inputs;
}

const EDGE_CASES = [
  '',
  ' ',
  '=',
  '==',
  '===',
  '====',
  'A',
  'A=',
  'A==',
  'A===',
  'AA',
  'AA=',
  'AA==',
  'AA===',
  'AB==',
  'AAA',
  'AAA=',
  'AAB=',
  'AAAA',
  'AAAA=',
  'AAAA====',
  '=AAA',
  'A=AA',
  'AA=A',
  '+/+/',
  '-_-_',
  '+/-_',
  '//==',
  'AAAA\n',
  ' AAAA',
  'AAéA',
  'ＡAAA',
];

test('the fast path answers what the full decode answers, input for input', () => {
  const inputs = [...EDGE_CASES, ...corpus(24_000, 0x5eed1e55)];
  const branches = { fast: 0, fullAccept: 0, reject: 0 };
  let ungatedWouldDiffer = 0;
  for (const text of inputs) {
    const expected = fullDecode(text);
    assert.deepEqual(withFastPath(text), expected, JSON.stringify(text));
    if (takesFastPath(text)) {
      assert.ok(expected.bytes !== undefined, `the gate let through ${JSON.stringify(text)}`);
      branches.fast += 1;
    } else if (expected.bytes !== undefined) {
      branches.fullAccept += 1;
    } else {
      branches.reject += 1;
    }
    if (
      expected.bytes === undefined ||
      Buffer.from(text, 'base64').toString('hex') !== expected.bytes
    ) {
      ungatedWouldDiffer += 1;
    }
  }
  // Each branch carried a real share of the corpus, so the equality above
  // was checked on all three.
  for (const [branch, count] of Object.entries(branches)) {
    assert.ok(count > 1000, `${branch} saw only ${count} inputs`);
  }
  // The corpus has teeth: Buffer.from without the gate would have answered
  // differently on thousands of these inputs.
  assert.ok(ungatedWouldDiffer > 1000, `an ungated fast path differs on ${ungatedWouldDiffer}`);
});
