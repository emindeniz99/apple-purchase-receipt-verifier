// Runs call files through this package's host layer (dist/engine.js: the
// jco bindings, the random-get import, one instance per configuration) and
// compares each answer, byte for byte, with a reference row file.
//
//   npm run build
//   node scripts/corpus.mjs CALLS_DIR ROWS_DIR [OUT_DIR] [corpus ...]
//
// CALLS_DIR holds <corpus>.pinned.jsonl in the call format of
// docs/evidence/2026-09-29-canonical-abi-final/py/calls_bytes.py (id, fn,
// config, now, env, b64; or id and map for a row with no call). ROWS_DIR
// holds module-<corpus>.jsonl, the reference answers. OUT_DIR, when given,
// receives node-<corpus>.jsonl. The corpora default to the five of the
// cross-host runs. Exits non-zero on any differing row or any trap.
import { createReadStream, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { join } from 'node:path';
import { InitRefusedError, Slot } from '../dist/engine.js';

const [callsDir, rowsDir, outDir, ...only] = process.argv.slice(2);
if (!callsDir || !rowsDir) {
  console.error('usage: corpus.mjs CALLS_DIR ROWS_DIR [OUT_DIR] [corpus ...]');
  process.exit(2);
}
const corpora = only.length > 0 ? only : ['algorithms', 'cases', 'fuzz', 'hostile', 'substrate'];
const utf8 = new TextEncoder();
const MAX_LIVE = 8;
const created = { count: 0 };

/** One row: `{id, out}`, `{id, trap}` or `{id, map}`, as the reference rows are. */
function answer(slots, row) {
  if ('map' in row) {
    return { id: row.id, map: row.map };
  }
  let slot = slots.get(row.config);
  if (slot === undefined) {
    try {
      slot = new Slot(utf8.encode(row.config));
    } catch (error) {
      if (error instanceof InitRefusedError) {
        return { id: row.id, out: error.answer };
      }
      return { id: row.id, trap: String(error?.message ?? error) };
    }
    slots.set(row.config, slot);
    created.count += 1;
    // A handful of live instances is enough; the fuzz corpus alone has 96
    // configurations, and an instance keeps whatever memory it grew to.
    if (slots.size > MAX_LIVE) {
      slots.delete(slots.keys().next().value);
    }
  }
  const input = Buffer.from(row.b64, 'base64');
  const now = BigInt(row.now);
  try {
    const out = slot.call((b) => {
      switch (row.fn) {
        case 'verify-receipt':
          return b.verifyReceipt(now, input);
        case 'verify-signed-data':
          return b.verifySignedData(now, input);
        case 'verify-receipt-endpoint':
          return b.verifyReceiptEndpoint(row.env, now, input);
        default:
          throw new Error(`unknown fn ${row.fn}`);
      }
    }, String);
    return { id: row.id, out };
  } catch (error) {
    slots.delete(row.config);
    return { id: row.id, trap: String(error?.message ?? error) };
  }
}

const key = (row) => JSON.stringify([row.out ?? null, row.trap ?? null, row.map ?? null]);
let failed = false;
for (const corpus of corpora) {
  const slots = new Map();
  created.count = 0;
  const rows = [];
  const lines = createInterface({
    input: createReadStream(join(callsDir, `${corpus}.pinned.jsonl`)),
    crlfDelay: Infinity,
  });
  const started = performance.now();
  // oxlint-disable-next-line no-await-in-loop -- one corpus at a time, each streamed
  for await (const line of lines) {
    if (line.trim() !== '') {
      rows.push(answer(slots, JSON.parse(line)));
    }
  }
  const seconds = (performance.now() - started) / 1000;
  const reference = readFileSync(join(rowsDir, `module-${corpus}.jsonl`), 'utf8')
    .split('\n')
    .filter((l) => l.trim() !== '')
    .map((l) => JSON.parse(l));
  if (reference.length !== rows.length) {
    throw new Error(`${corpus}: ${rows.length} rows, the reference has ${reference.length}`);
  }
  const differ = [];
  let traps = 0;
  rows.forEach((row, i) => {
    if (row.id !== reference[i].id) {
      throw new Error(`${corpus} row ${i}: id ${row.id}, the reference has ${reference[i].id}`);
    }
    traps += 'trap' in row ? 1 : 0;
    if (key(row) !== key(reference[i])) {
      differ.push(row.id);
    }
  });
  if (outDir) {
    mkdirSync(outDir, { recursive: true });
    writeFileSync(
      join(outDir, `node-${corpus}.jsonl`),
      `${rows.map((r) => JSON.stringify(r)).join('\n')}\n`,
    );
  }
  console.log(
    `${corpus}: ${rows.length} rows, ${rows.length - differ.length} identical, ` +
      `${differ.length} differ, ${traps} traps, ${created.count} instances, ${seconds.toFixed(1)} s`,
  );
  for (const id of differ) {
    console.log(`  differs: ${id}`);
  }
  failed ||= differ.length > 0 || traps > 0;
}
process.exit(failed ? 1 : 0);
