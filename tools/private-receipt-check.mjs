#!/usr/bin/env node
// The private-receipt drift check (MIGRATION.md step 1.9): does the core
// still read what Apple sends? Runs every file of a directory OUTSIDE the
// repository through aprv.wasm and prints, per file, only the verdict, the
// reason and the unknown attribute type numbers; never a value, never a
// message, never a file name (a line names its file by its position in the
// sorted listing, so the owner can map it back locally).
//
//   node tools/private-receipt-check.mjs <dir> [--module <aprv.wasm>] [--root <der>]...
//
// The module is APRV_WASM unless --module names one (build it with
// rust/bindings/abi/build.sh <out>). Production receipts never enter the
// repository, its history, CI, an issue or a PR, and neither does this
// script's output when it ran on them (CLAUDE.md, "Fixtures and privacy");
// a new attribute type becomes a test built from a generated receipt of
// the same shape.
//
// A file is read as: DER (first byte 0x30), a compact JWS (three
// base64url segments), a verifyReceipt request body ({"receipt-data":
// "..."}, its receipt-data taken), or else base64 receipt-data. Everything
// verifies at the current time under Apple's three roots, or under the
// DER roots --root names (the test runs generated receipts that way).
//
// Output, one line per file, then a summary:
//   #<n> receipt verified unknown=<t,...> in_app_unknown=<t,...>
//   #<n> receipt refused <REASON>
//   #<n> jws verified
//   #<n> jws refused <REASON>
// Exit status 0 when every file ran, 1 on a trap, 2 on a usage error.
import { readFileSync, readdirSync, statSync, realpathSync } from 'node:fs';
import { getRandomValues } from 'node:crypto';
import { join, resolve, sep, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const IFACE = 'aprv:verifier/verify@0.1.0#';
const HOST = 'aprv:verifier/host@0.1.0';

function usage(message) {
  console.error(`private-receipt-check: ${message}\nusage: node tools/private-receipt-check.mjs <dir> [--module <aprv.wasm>] [--root <der>]...`);
  process.exit(2);
}

let args;
try {
  args = parseArgs({ allowPositionals: true, options: { module: { type: 'string' }, root: { type: 'string', multiple: true, default: [] } } });
} catch (error) {
  usage(error.message);
}
const modulePath = args.values.module ?? process.env.APRV_WASM;
const roots = args.values.root.map((path) => readFileSync(path).toString('base64'));
if (args.positionals.length !== 1) usage('name one directory');
if (!modulePath) usage('no module: set APRV_WASM or pass --module');
const dir = realpathSync(resolve(args.positionals[0]));
const repo = realpathSync(resolve(dirname(fileURLToPath(import.meta.url)), '..'));
if (dir === repo || dir.startsWith(repo + sep)) usage('the directory is inside the repository; keep private receipts outside it');

// --- the canonical ABI, called by hand (no verification logic here) -----
const utf8 = new TextDecoder('utf-8', { fatal: true });
const enc = new TextEncoder();
class Guest {
  constructor(module) {
    const imports = {};
    for (const imp of WebAssembly.Module.imports(module)) {
      if (imp.module !== HOST || imp.name !== 'random-get') throw new Error(`unexpected import ${imp.module} ${imp.name}`);
    }
    imports[HOST] = {
      'random-get': (len, retptr) => {
        const n = len >>> 0;
        const bytes = new Uint8Array(n);
        for (let i = 0; i < n; i += 65536) getRandomValues(bytes.subarray(i, Math.min(n, i + 65536)));
        const ptr = this.exports.cabi_realloc(0, 0, 1, n) >>> 0;
        new Uint8Array(this.exports.memory.buffer, ptr, n).set(bytes);
        const view = new DataView(this.exports.memory.buffer);
        view.setUint32(retptr >>> 0, ptr, true);
        view.setUint32((retptr >>> 0) + 4, n, true);
      },
    };
    this.exports = new WebAssembly.Instance(module, imports).exports;
    if (typeof this.exports._initialize === 'function') this.exports._initialize();
  }

  call(fn, ...args) {
    const lowered = args.flatMap((a) => {
      if (typeof a === 'bigint') return [BigInt.asIntN(64, a)];
      const ptr = this.exports.cabi_realloc(0, 0, 1, a.length) >>> 0;
      new Uint8Array(this.exports.memory.buffer, ptr, a.length).set(a);
      return [ptr | 0, a.length];
    });
    const retptr = this.exports[IFACE + fn](...lowered) >>> 0;
    const view = new DataView(this.exports.memory.buffer);
    const ptr = view.getUint32(retptr, true);
    const len = view.getUint32(retptr + 4, true);
    const text = utf8.decode(new Uint8Array(this.exports.memory.buffer, ptr, len).slice());
    this.exports[`cabi_post_${IFACE}${fn}`](retptr | 0);
    return text;
  }
}

const module = new WebAssembly.Module(readFileSync(modulePath));
let guest;
const fresh = () => {
  guest = new Guest(module);
  const answer = guest.call('init', enc.encode(JSON.stringify({ roots })));
  if (JSON.parse(answer).ok !== true) usage('init refused the roots');
};
fresh();

const JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$/;
function input(bytes) {
  if (bytes[0] === 0x30) return { kind: 'receipt', bytes: enc.encode(Buffer.from(bytes).toString('base64')) };
  const text = Buffer.from(bytes).toString('utf8').trim();
  if (JWS.test(text)) return { kind: 'jws', bytes: enc.encode(text) };
  if (text.startsWith('{')) {
    try {
      const data = JSON.parse(text)['receipt-data'];
      if (typeof data === 'string') return { kind: 'receipt', bytes: enc.encode(data) };
    } catch {
      // not a request body: read as receipt-data below
    }
  }
  return { kind: 'receipt', bytes: enc.encode(text) };
}

const types = (unknown) =>
  Object.keys(unknown ?? {})
    .map(Number)
    .sort((a, b) => a - b)
    .join(',');

const files = readdirSync(dir)
  .filter((name) => statSync(join(dir, name)).isFile())
  .sort();
const counts = { verified: 0, refused: 0, trapped: 0 };
const newTypes = { receipt: new Set(), inApp: new Set() };
files.forEach((name, i) => {
  const { kind, bytes } = input(readFileSync(join(dir, name)));
  let result;
  try {
    const now = BigInt(Date.now());
    result = JSON.parse(kind === 'jws' ? guest.call('verify-signed-data', now, bytes) : guest.call('verify-receipt', now, bytes));
  } catch {
    counts.trapped++;
    console.log(`#${i + 1} ${kind} trapped`);
    fresh(); // a trapped instance is discarded
    return;
  }
  if (result.verified !== true) {
    counts.refused++;
    console.log(`#${i + 1} ${kind} refused ${String(result.reason).replace(/[^A-Z_]/g, '')}`);
    return;
  }
  counts.verified++;
  if (kind === 'jws') {
    console.log(`#${i + 1} jws verified`);
    return;
  }
  const payload = result.payload;
  const top = types(payload.unknown_attributes);
  const inApp = [...new Set((payload.in_app ?? []).flatMap((p) => Object.keys(p.unknown_attributes ?? {}).map(Number)))].sort((a, b) => a - b);
  top.split(',').filter(Boolean).forEach((t) => newTypes.receipt.add(Number(t)));
  inApp.forEach((t) => newTypes.inApp.add(t));
  console.log(`#${i + 1} receipt verified unknown=${top} in_app_unknown=${inApp.join(',')}`);
});
const list = (set) => [...set].sort((a, b) => a - b).join(',');
console.log(
  `summary: ${files.length} files, ${counts.verified} verified, ${counts.refused} refused, ${counts.trapped} trapped; ` +
    `unknown receipt types ${list(newTypes.receipt) || 'none'}; unknown in_app types ${list(newTypes.inApp) || 'none'}`,
);
process.exit(counts.trapped ? 1 : 0);
