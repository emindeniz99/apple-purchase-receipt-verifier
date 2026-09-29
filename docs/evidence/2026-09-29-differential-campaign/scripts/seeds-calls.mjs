#!/usr/bin/env node
// Evidence only (2026-09-29). The ports' fuzz seeds as one call file for
// the differential campaign, in tools/wasm-trap-host.mjs's `calls` format.
//
//   node seeds-calls.mjs <repo> > seeds.jsonl
//
// What the ports' fuzzers start from, as found in the repository:
//   - the endpoint-json seed files of rust/, node/, python/, swift/, php/
//     and dotnet/ (plus dotnet's JSON-reader seeds), deduplicated by
//     content, as request bodies in both environments;
//   - Go's inline seeds (go/fuzz_test.go: the fixture ids it names, "",
//     "!!!!not base64!!!!", "a.b.c");
//   - the fixture directories every other fuzzer seeds from (Jazzer,
//     atheris, ruzzy, libFuzzer Swift, SharpFuzz, PHP, cargo-fuzz):
//     fixtures/generated, fixtures/generated-0.7, fixtures/apple-official
//     and fixtures/public-receipts, each file sniffed as DER, base64 text,
//     hex, a compact JWS or a JSON body.
// Each receipt or JWS runs under Apple's roots and under every registered
// trust-anchor fixture that decodes as a certificate, so a seed reaches the
// chain and the signature, not only the envelope.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { createHash, X509Certificate } from 'node:crypto';
import { join, relative } from 'node:path';

const NOW = 1790640000000; // 2026-09-29T00:00:00Z, as the pinned corpora
const repo = process.argv[2];
if (!repo) {
  console.error('usage: seeds-calls.mjs <repo>');
  process.exit(2);
}
const cases = JSON.parse(readFileSync(join(repo, 'fixtures/cases.json'), 'utf8'));
const anchors = [];
for (const [id, f] of Object.entries(cases.fixtures)) {
  if (f.role !== 'trust-anchor') continue;
  let der = readFileSync(join(repo, 'fixtures', f.path));
  if (f.codec === 'base64') der = Buffer.from(der.toString('ascii').replace(/\s+/g, ''), 'base64');
  try {
    new X509Certificate(der);
    anchors.push(der.toString('base64'));
  } catch {
    console.error(`seeds-calls: trust anchor ${id} does not decode; left out`);
  }
}
const CONFIGS = { apple: JSON.stringify({ roots: [] }), anchors: JSON.stringify({ roots: [...new Set(anchors)] }) };

const walk = (dir) =>
  readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });

const out = [];
const seen = new Set();
const push = (id, fn, bytes, env) => {
  const key = `${fn}\0${env ?? ''}\0${createHash('sha256').update(bytes).digest('hex')}`;
  if (seen.has(key)) return;
  seen.add(key);
  const configs = fn === 'verify-receipt-endpoint' ? ['apple'] : ['apple', 'anchors'];
  for (const c of configs) {
    const row = { id: `seeds/${c}/${id}`, fn, config: CONFIGS[c], now: NOW, b64: Buffer.from(bytes).toString('base64') };
    if (env !== undefined) row.env = env;
    out.push(row);
  }
};

// 1. endpoint-json seeds of every port.
for (const dir of ['rust/fuzz/seeds', 'node/fuzz/seeds', 'python/fuzz/seeds', 'swift/fuzz/seeds', 'php/fuzz/seeds', 'dotnet/fuzz/seeds']) {
  let files;
  try {
    files = walk(join(repo, dir));
  } catch {
    continue;
  }
  for (const file of files) {
    const bytes = readFileSync(file);
    for (const env of [0, 1]) push(`${relative(repo, file)}#env${env}`, 'verify-receipt-endpoint', bytes, env);
  }
}

// 2. Go's inline seeds besides the fixtures it names (those come in with 3).
push('go/fuzz_test.go#receipt-empty', 'verify-receipt', Buffer.alloc(0));
push('go/fuzz_test.go#receipt-not-base64', 'verify-receipt', Buffer.from('!!!!not base64!!!!'));
push('go/fuzz_test.go#jws-empty', 'verify-signed-data', Buffer.alloc(0));
push('go/fuzz_test.go#jws-a.b.c', 'verify-signed-data', Buffer.from('a.b.c'));

// 3. The shared fixture directories, sniffed.
const B64 = /^[A-Za-z0-9+/=\s]+$/;
const JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$/;
for (const dir of ['fixtures/generated', 'fixtures/generated-0.7', 'fixtures/apple-official', 'fixtures/public-receipts']) {
  for (const file of walk(join(repo, dir)).sort()) {
    const name = relative(repo, file);
    if (/(LICENSE|README|\.md$|\.pem$)/.test(name)) continue;
    const bytes = readFileSync(file);
    const text = bytes.toString('utf8').trim();
    if (bytes[0] === 0x30) {
      push(name, 'verify-receipt', Buffer.from(bytes.toString('base64')));
    } else if (JWS.test(text)) {
      push(name, 'verify-signed-data', Buffer.from(text));
    } else if (name.endsWith('.hex') && /^[0-9a-fA-F\s]+$/.test(text)) {
      push(name, 'verify-receipt', Buffer.from(Buffer.from(text.replace(/\s+/g, ''), 'hex').toString('base64')));
    } else if (name.endsWith('.json')) {
      for (const env of [0, 1]) push(`${name}#env${env}`, 'verify-receipt-endpoint', bytes, env);
    } else if (B64.test(text)) {
      push(name, 'verify-receipt', Buffer.from(text));
    } else {
      // Anything else still goes in, as both inputs: the fuzzers see it so.
      push(`${name}#as-receipt`, 'verify-receipt', bytes);
      push(`${name}#as-jws`, 'verify-signed-data', bytes);
    }
  }
}
process.stdout.write(out.map((r) => `${JSON.stringify(r)}\n`).join(''));
console.error(`seeds-calls: ${out.length} calls, ${anchors.length} trust anchors in the anchors config`);
