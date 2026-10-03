#!/usr/bin/env node
// Compares the core's rows with the Java implementation's for the
// differential campaign (DECISIONS.md R33): the comparison step of
// tools/differential.sh.
//
//   node tools/differential/compare.mjs <core.jsonl> <java.jsonl> [--recorded <recorded.json>]... [--list]
//
// Both files hold one {"id", "out" | "map" | "trap" | "threw"} row per call,
// in the same order: the core's from `tools/wasm-trap-host.mjs calls`, the
// Java implementation's from Differential.java. Each pair lands in one class:
//
//   same             same verdict and reason; for a verified row, the same
//                    payload by value (an endpoint row: the same status and,
//                    for status 0, the same body by value)
//   message-only     same verdict and reason, other message text
//   java-no-call     the Java API cannot express the call (a map row: input
//                    bytes that are not UTF-8, a root that does not decode)
//   reason           both refuse, for different reasons
//   payload          both verify, with different payloads
//   verdict          one verifies and the other refuses
//   fault            a trap, an exception, or INTERNAL_ERROR on either side
//
// `recorded.json` maps a row id to the class R20 records for it, with the
// row's reason (see tools/differential/README.md). The exit status is 1 when
// a row's class is reason, payload, verdict or fault and the recorded file
// does not name that id with that class; a recorded row that now answers the
// same is reported as stale but does not fail the run.
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

function usage() {
  console.error('usage: compare.mjs <core.jsonl> <java.jsonl> [--recorded <recorded.json>] [--list]');
  process.exit(2);
}
let args;
try {
  args = parseArgs({ allowPositionals: true, options: { recorded: { type: 'string', multiple: true, default: [] }, list: { type: 'boolean' } } });
} catch {
  usage();
}
const { recorded: recordedPaths, list } = args.values;
const files = args.positionals;
if (files.length !== 2) usage();

// Integer literals a double cannot hold stay exact (the endpoint's ids).
const BIG = '__big__:';
const LITERAL = /"(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
const parse = (text) =>
  JSON.parse(
    text.replace(LITERAL, (l) => (l.startsWith('"') || !/^-?\d+$/.test(l) || Number.isSafeInteger(Number(l)) ? l : `"${BIG}${l}"`)),
  );
const same = (a, b) => {
  if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') return Object.is(a, b);
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const ka = Object.keys(a);
  return ka.length === Object.keys(b).length && ka.every((k) => Object.hasOwn(b, k) && same(a[k], b[k]));
};
const rows = (path) =>
  readFileSync(path, 'utf8')
    .split('\n')
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l));

/** What one side answered: {kind: ok|fail|endpoint|config|map|fault, ...}. */
function outcome(row) {
  // A root that is not a certificate: the core's init refuses it, Java's
  // CertificateFactory does; the same answer, reached before any call.
  if (row.map === 'root-not-a-certificate') return { kind: 'config' };
  if (row.map !== undefined) return { kind: 'map', map: row.map };
  if (row.trap !== undefined) return { kind: 'fault', detail: `trap ${row.trap}` };
  if (row.threw !== undefined) return { kind: 'fault', detail: `threw ${row.threw}` };
  let doc;
  try {
    doc = parse(row.out);
  } catch {
    return { kind: 'fault', detail: `not JSON: ${String(row.out).slice(0, 80)}` };
  }
  if (doc !== null && typeof doc === 'object' && doc.ok === false) return { kind: 'config' };
  if (doc !== null && typeof doc === 'object' && 'status' in doc && !('verified' in doc)) {
    return { kind: 'endpoint', status: doc.status, doc };
  }
  if (doc.verified === true) {
    const payload = typeof doc.payload === 'string' ? parse(doc.payload) : doc.payload;
    return { kind: 'ok', payload };
  }
  if (doc.reason === 'INTERNAL_ERROR') return { kind: 'fault', detail: `INTERNAL_ERROR ${doc.message}` };
  return { kind: 'fail', reason: doc.reason, message: doc.message };
}

function classify(core, java) {
  if (core.kind === 'fault' || java.kind === 'fault') return 'fault';
  if (java.kind === core.kind && (core.kind === 'map' || core.kind === 'config')) return 'same';
  if (java.kind === 'map') return 'java-no-call';
  if (core.kind === 'endpoint' && java.kind === 'endpoint') {
    if (core.status !== java.status) return (core.status === 0) !== (java.status === 0) ? 'verdict' : 'reason';
    return core.status === 0 && !same(core.doc, java.doc) ? 'payload' : 'same';
  }
  if (core.kind !== java.kind) return 'verdict';
  if (core.kind === 'ok') return same(core.payload, java.payload) ? 'same' : 'payload';
  if (core.reason !== java.reason) return 'reason';
  return core.message === java.message ? 'same' : 'message-only';
}

const brief = (o) =>
  o.kind === 'ok'
    ? 'verified'
    : o.kind === 'fail'
      ? `${o.reason}: ${o.message}`
      : o.kind === 'endpoint'
        ? `status ${o.status}`
        : o.kind === 'map'
          ? `no call (${o.map})`
          : o.kind === 'config'
            ? 'the config is refused'
            : o.detail;

const a = rows(files[0]);
const b = rows(files[1]);
if (a.length !== b.length) {
  console.error(`compare: ${a.length} core rows, ${b.length} Java rows`);
  process.exit(2);
}
const recorded = Object.assign({}, ...recordedPaths.map((p) => JSON.parse(readFileSync(p, 'utf8')).rows ?? {}));
const counts = {};
const unrecorded = [];
const stale = [];
const detail = [];
a.forEach((x, i) => {
  const y = b[i];
  if (x.id !== y.id) {
    console.error(`compare: row ${i} is ${x.id} in the core's file and ${y.id} in Java's`);
    process.exit(2);
  }
  const core = outcome(x);
  const java = outcome(y);
  const cls = classify(core, java);
  counts[cls] = (counts[cls] ?? 0) + 1;
  const rec = recorded[x.id];
  const failing = ['reason', 'payload', 'verdict', 'fault'].includes(cls);
  if (failing && rec?.class !== cls) unrecorded.push(x.id);
  if (rec && !failing) stale.push(x.id);
  if (failing || (list && cls !== 'same')) detail.push(`${cls.padEnd(12)} ${x.id}\n    core: ${brief(core)}\n    java: ${brief(java)}${rec ? `\n    recorded: ${rec.class}` : ''}`);
});
for (const line of detail) console.log(line);
console.log(
  `summary: ${a.length} rows; ${Object.entries(counts)
    .sort()
    .map(([k, v]) => `${v} ${k}`)
    .join(', ')}; ${unrecorded.length} not recorded in R20; ${stale.length} recorded rows now agree`,
);
for (const id of unrecorded) console.log(`NOT RECORDED ${id}`);
for (const id of stale) console.log(`STALE ${id}`);
process.exit(unrecorded.length ? 1 : 0);
