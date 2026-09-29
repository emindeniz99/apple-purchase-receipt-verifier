// tools/private-receipt-check.mjs on a directory of generated receipts
// (MIGRATION.md step 1.9): it runs every file, and its output holds no
// value from any of them, only verdicts, reasons and attribute type
// numbers.
//
//   APRV_WASM=<out>/aprv.wasm node --test tools/test/private-receipt-check.test.mjs
//
// Needs the built module (rust/bindings/abi/build.sh <out>); without
// APRV_WASM every test fails with that message, nothing is skipped.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const tools = join(dirname(fileURLToPath(import.meta.url)), '..');
const fixtures = join(tools, '..', 'fixtures');
const script = join(tools, 'private-receipt-check.mjs');
const LINE = /^#\d+ (receipt|jws) (verified( unknown=[0-9,]* in_app_unknown=[0-9,]*)?|refused [A-Z_]+|trapped)$/;
const SUMMARY = /^summary: \d+ files, \d+ verified, \d+ refused, \d+ trapped; unknown receipt types [0-9,a-z]+; unknown in_app types [0-9,a-z]+$/;

function module() {
  const path = process.env.APRV_WASM;
  assert.ok(path, 'APRV_WASM is not set: build the module with rust/bindings/abi/build.sh <out> and set APRV_WASM=<out>/aprv.wasm');
  return path;
}

/** Generated receipts and transactions, copied outside the repository. */
function directory() {
  const dir = mkdtempSync(join(tmpdir(), 'aprv-private-check-'));
  for (const sub of ['generated', 'generated-0.7']) {
    for (const name of readdirSync(join(fixtures, sub))) {
      if (/^(receipt|transaction|app-transaction).*\.(der|jws)$/.test(name) && !name.endsWith('-root.der')) {
        copyFileSync(join(fixtures, sub, name), join(dir, `${sub}-${name}`));
      }
    }
  }
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function run(dir, ...extra) {
  const result = spawnSync(process.execPath, [script, dir, '--module', module(), ...extra], { encoding: 'utf8' });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

/** Every string and every long number a verified payload of these files carries. */
function secrets(dir) {
  const values = new Set(['com.example.app']);
  for (const name of readdirSync(dir)) {
    const text = readFileSync(join(dir, name), 'utf8');
    if (!name.endsWith('.jws')) continue;
    const payload = text.trim().split('.')[1];
    if (!payload) continue;
    let claims;
    try {
      claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    } catch {
      continue;
    }
    if (claims === null || typeof claims !== 'object') continue;
    for (const v of Object.values(claims)) {
      if (typeof v === 'string' && v.length >= 4) values.add(v);
      if (typeof v === 'number' && String(v).length >= 5) values.add(String(v));
    }
  }
  return values;
}

test('every file runs and every line is a verdict, a reason and type numbers', () => {
  const { dir, cleanup } = directory();
  try {
    const files = readdirSync(dir).length;
    assert.ok(files >= 20, `only ${files} generated inputs copied`);
    for (const roots of [[], ['--root', join(fixtures, 'generated-0.7/receipt-root.der')], ['--root', join(fixtures, 'generated/jws-root.der')]]) {
      const { status, stdout, stderr } = run(dir, ...roots);
      assert.equal(status, 0, stderr);
      const lines = stdout.trimEnd().split('\n');
      assert.equal(lines.length, files + 1, stdout);
      for (const line of lines.slice(0, -1)) assert.match(line, LINE);
      assert.match(lines.at(-1), SUMMARY);
    }
  } finally {
    cleanup();
  }
});

test('the output carries no value of the receipts it verified', () => {
  const { dir, cleanup } = directory();
  try {
    const receipts = run(dir, '--root', join(fixtures, 'generated-0.7/receipt-root.der'));
    const transactions = run(dir, '--root', join(fixtures, 'generated/jws-root.der'));
    // The check must have read payloads for the assertion to mean anything.
    assert.match(receipts.stdout, /receipt verified unknown=\d/);
    assert.match(transactions.stdout, /jws verified/);
    const output = receipts.stdout + receipts.stderr + transactions.stdout + transactions.stderr;
    for (const name of readdirSync(dir)) assert.ok(!output.includes(name), `a file name reached the output: ${name}`);
    for (const value of secrets(dir)) assert.ok(!output.includes(value), `a payload value reached the output: ${value}`);
    // Nothing but the grammar: no JSON, no base64 of any length.
    assert.doesNotMatch(output, /[{}"]|[A-Za-z0-9+/]{12,}/);
  } finally {
    cleanup();
  }
});

test('it refuses a directory inside the repository', () => {
  const result = spawnSync(process.execPath, [script, join(fixtures, 'generated'), '--module', module()], { encoding: 'utf8' });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /inside the repository/);
});
