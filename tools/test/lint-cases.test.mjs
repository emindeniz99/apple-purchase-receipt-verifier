// Tests for tools/lint-cases.mjs. Each test plants one schema violation in
// a temporary copy of fixtures/ and checks that the linter fails on exactly
// that problem, naming the case and the JSON path, rather than on every
// oneOf branch the case was not meant to match.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const tool = fileURLToPath(new URL('../lint-cases.mjs', import.meta.url));
const fixtures = fileURLToPath(new URL('../../fixtures', import.meta.url));
const original = readFileSync(join(fixtures, 'cases.json'), 'utf8');

const scratch = mkdtempSync(join(tmpdir(), 'lint-cases-'));
const copy = join(scratch, 'fixtures');
cpSync(fixtures, copy, { recursive: true });
test.after(() => rmSync(scratch, { recursive: true, force: true }));

function run(dir) {
  const r = spawnSync(process.execPath, [tool, '--fixtures', dir], { encoding: 'utf8' });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

// Plants a violation in the case `pick` selects, lints the copy, and
// returns the result with that case's index and id.
function plant(pick, mutate) {
  const doc = JSON.parse(original);
  const index = doc.cases.findIndex(pick);
  assert.ok(index >= 0, 'no case to plant in');
  const { id } = doc.cases[index];
  mutate(doc.cases[index]);
  writeFileSync(join(copy, 'cases.json'), JSON.stringify(doc, null, 2));
  return { ...run(copy), index, id };
}

function assertOneProblem(r, path, message) {
  assert.equal(r.code, 1, r.err);
  const problems = r.err.split('\n').filter((line) => line.startsWith('  - '));
  assert.deepEqual(problems, [`  - case #${r.index} "${r.id}": /cases/${r.index}${path} ${message}`]);
}

test('the repository fixtures pass', () => {
  const r = run(fixtures);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /lint-cases: OK — \d+ cases over \d+ registered fixtures\./);
});

test('a missing required property is one problem at the case', () => {
  const r = plant(() => true, (c) => { delete c.description; });
  assertOneProblem(r, '', "must have required property 'description'");
});

test('a wrong type names the property and the value it got', () => {
  const r = plant((c) => c.maxMillis !== undefined, (c) => { c.maxMillis = '100'; });
  assertOneProblem(r, '/maxMillis', 'must be integer, got "100"');
});

test('an unknown property names the property', () => {
  const r = plant(() => true, (c) => { c.bogus = 1; });
  assertOneProblem(r, '', 'must NOT have additional properties: "bogus"');
});

// expected is a oneOf of the ok, error and oneOf shapes; the ok shape is
// the closest, so its missing environment is the one problem reported.
test('an ok receipt case without environment reports that, not the other shapes', () => {
  const r = plant((c) => c.operation === 'verifyReceipt' && c.expected.status === 'ok',
    (c) => { delete c.expected.environment; });
  assertOneProblem(r, '/expected', "must have required property 'environment'");
});

test('a trustedRoots matching no shape reports the closest shape\'s problem', () => {
  const r = plant((c) => c.config?.trustedRoots?.source === 'defaults',
    (c) => { c.config.trustedRoots.source = 'bundled'; });
  assertOneProblem(r, '/config/trustedRoots/source', 'must be equal to constant "defaults", got "bundled"');
});

test('usage errors exit 2', () => {
  const r = spawnSync(process.execPath, [tool, '--nope'], { encoding: 'utf8' });
  assert.equal(r.status, 2);
});
