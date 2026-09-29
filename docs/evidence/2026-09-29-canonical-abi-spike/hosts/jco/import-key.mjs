// Spike only (2026-09-29, round 12). Which import key jco 1.35.0's glue
// accepts: the versioned one its .d.ts declares, or the unversioned one.
//   node import-key.mjs $S/jco/out
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
const out = process.argv[2];
const { instantiate } = await import(join(out, 'aprv.js'));
const gc = (n) => WebAssembly.compile(readFileSync(join(out, n)));
const host = { randomGet: (n) => new Uint8Array(n) };
for (const key of ['aprv:verifier/host@1.0.0', 'aprv:verifier/host']) {
  try { const r = await instantiate(gc, { [key]: host }); console.log(key, '->', r.verify.init('')); }
  catch (e) { console.log(key, '-> THROWS', String(e).split('\n')[0]); }
}
