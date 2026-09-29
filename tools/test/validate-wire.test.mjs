// Tests for tools/validate-wire.mjs, on a test-only pair of schemas that
// $ref each other, like the wire schemas in rust/bindings/wire/schema/.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const tool = fileURLToPath(new URL('../validate-wire.mjs', import.meta.url));
const fx = (p) => fileURLToPath(new URL(`fixtures/validate-wire/${p}`, import.meta.url));
const schema = fx('schema/result.schema.json');

function run(...args) {
  const r = spawnSync(process.execPath, [tool, ...args], { encoding: 'utf8' });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

test('valid answers pass, blank lines are skipped, and a $ref to a sibling file resolves', () => {
  const r = run(schema, fx('good.jsonl'));
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /3 answers in good\.jsonl validate/);
});

test('a planted wrong type fails on its own line, and nothing after it is read', () => {
  const r = run(schema, fx('bad-type.jsonl'));
  assert.equal(r.code, 1);
  assert.match(r.err, /bad-type\.jsonl:2 does not validate/);
  assert.match(r.err, /\/payload\/id must be string/);
  assert.doesNotMatch(r.err, /never reached/);
});

test('an empty answers file fails: no answers proves nothing', () => {
  const r = run(schema, fx('empty.jsonl'));
  assert.equal(r.code, 1);
  assert.match(r.err, /holds no answers/);
});

test('--field reads rows whose answer is JSON text or a JSON value', () => {
  const r = run(schema, fx('rows.jsonl'), '--field', 'out');
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /2 answers/);
});

test('--field fails on a row without the field (a trap row is not an answer)', () => {
  const r = run(schema, fx('rows-missing.jsonl'), '--field', 'out');
  assert.equal(r.code, 1);
  assert.match(r.err, /rows-missing\.jsonl:2 \(case\/trapped\): not an answer/);
});

test('a schema with an unknown keyword is refused rather than accepting everything', () => {
  const r = run(fx('typo-schema/typo.schema.json'), fx('good.jsonl'));
  assert.equal(r.code, 2);
  assert.match(r.err, /requird/);
});

test('usage errors exit 2', () => {
  assert.equal(run().code, 2);
  assert.equal(run(schema).code, 2);
  assert.equal(run(schema, fx('good.jsonl'), '--nope').code, 2);
});
