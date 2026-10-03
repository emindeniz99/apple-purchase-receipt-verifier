#!/usr/bin/env node
// Turns fixtures/cases.json into a call file for the differential campaign
// (tools/differential.sh), in the format tools/wasm-trap-host.mjs reads in
// its `calls` mode and Differential.java reads: one
// {"id","fn","config","now","b64"[,"env"]} object per call.
//
//   node tools/differential/cases-calls.mjs fixtures/cases.json > calls.jsonl
//
// Each verify case is one call, its input built as SURFACE.md §6 and the
// file's own comment say (a raw or base64 fixture as canonical base64, a
// text fixture verbatim, an endpoint fixture wrapped as
// {"receipt-data": ...}). A decodeBase64 case becomes one call per text:
// a receipt-data text through verify-receipt, an x5c text as all three x5c
// entries of a JWS header through verify-signed-data (the probe the host
// runners use), with ids `<case>#receipt-data/<i>` and `<case>#x5c/<i>`.
// A case without a clock runs at one pinned instant, so both
// implementations judge a dateless input at the same moment.
import { readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { readFixture } from '../lib/fixtures.mjs';

const PINNED_NOW = 1790640000000; // 2026-09-29T00:00:00Z

const path = process.argv[2];
if (!path) {
  console.error('usage: cases-calls.mjs <cases.json>');
  process.exit(2);
}
const doc = JSON.parse(readFileSync(path, 'utf8'));
const base = dirname(path);
const cache = new Map();

function fixture(id) {
  if (cache.has(id)) return cache.get(id);
  const entry = doc.fixtures[id];
  if (entry === undefined) throw new Error(`cases.json registers no fixture "${id}"`);
  const value = { entry, bytes: readFixture(base, entry, id) };
  cache.set(id, value);
  return value;
}

const receiptText = ({ entry, bytes }) =>
  entry.codec === 'raw' || entry.codec === 'base64' ? bytes.toString('base64') : bytes.toString('utf8');

function config(kase) {
  const spec = kase.config?.trustedRoots;
  const roots =
    spec === undefined || spec.source === 'defaults' ? [] : spec.fixtures.map((id) => fixture(id).bytes.toString('base64'));
  return JSON.stringify({ roots });
}

function now(kase) {
  if (kase.clock?.now === undefined) return PINNED_NOW;
  const ms = Date.parse(kase.clock.now);
  if (Number.isNaN(ms)) throw new Error(`${kase.id}: unparseable clock "${kase.clock.now}"`);
  return ms;
}

const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const b64url = (s) => Buffer.from(s).toString('base64url');
const x5cProbe = (text) => `${b64url(JSON.stringify({ alg: 'ES256', x5c: [text, text, text] }))}.${b64url('{}')}.${b64url('signature')}`;

const out = [];
for (const kase of doc.cases) {
  const cfg = config(kase);
  const at = now(kase);
  switch (kase.operation) {
    case 'verifyReceipt':
      out.push({ id: kase.id, fn: 'verify-receipt', config: cfg, now: at, b64: b64(receiptText(fixture(kase.input.fixture))) });
      break;
    case 'verifySignedData':
      out.push({ id: kase.id, fn: 'verify-signed-data', config: cfg, now: at, b64: b64(fixture(kase.input.fixture).bytes) });
      break;
    case 'verifyReceiptEndpoint': {
      const env = { PRODUCTION: 0, SANDBOX: 1 }[kase.config.environment];
      if (env === undefined) throw new Error(`${kase.id}: unknown environment ${kase.config.environment}`);
      const body =
        kase.input.requestBody !== undefined
          ? fixture(kase.input.requestBody).bytes
          : Buffer.from(JSON.stringify({ 'receipt-data': receiptText(fixture(kase.input.fixture)) }));
      out.push({ id: kase.id, fn: 'verify-receipt-endpoint', config: cfg, now: at, env, b64: b64(body) });
      break;
    }
    case 'decodeBase64':
      for (const decoder of kase.decoders) {
        kase.input.texts.forEach((text, i) => {
          const id = `${kase.id}#${decoder}/${i}`;
          if (decoder === 'receipt-data') {
            out.push({ id, fn: 'verify-receipt', config: cfg, now: at, b64: b64(text) });
          } else if (decoder === 'x5c') {
            out.push({ id, fn: 'verify-signed-data', config: cfg, now: at, b64: b64(x5cProbe(text)) });
          } else {
            throw new Error(`${kase.id}: no decoder ${decoder}`);
          }
        });
      }
      break;
    default:
      throw new Error(`${kase.id}: no mapping for operation ${kase.operation}`);
  }
}
process.stdout.write(out.map((r) => `${JSON.stringify(r)}\n`).join(''));
console.error(`cases-calls: ${doc.cases.length} cases, ${out.length} calls`);
