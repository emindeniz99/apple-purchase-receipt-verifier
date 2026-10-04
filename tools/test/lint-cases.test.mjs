// Tests for tools/lint-cases.mjs. Each test plants schema violations in a
// temporary copy of cases.json (and, for some, of cases.schema.json) and
// checks that the linter reports exactly those problems, one line each,
// naming the case and the JSON path, rather than one line per oneOf branch
// the case was not meant to match. The table below is the evidence that the
// move from a hand-written validator to Ajv still catches what it caught.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  copyFileSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync,
  symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const tool = fileURLToPath(new URL('../lint-cases.mjs', import.meta.url));
const fixtures = realpathSync(fileURLToPath(new URL('../../fixtures', import.meta.url)));
const cases = readFileSync(join(fixtures, 'cases.json'), 'utf8');
const schema = readFileSync(join(fixtures, 'cases.schema.json'), 'utf8');

// The copy holds its own cases.json and cases.schema.json and links every
// other entry (the fixture tiers) to the real one, so a run reads the same
// fixture files without copying 35 MB. The two planted files must be real
// files in a real directory, or a write would land in the repository.
const scratch = mkdtempSync(join(tmpdir(), 'lint-cases-'));
const copy = join(scratch, 'fixtures');
mkdirSync(copy);
for (const name of readdirSync(fixtures)) {
  if (name === 'cases.json' || name === 'cases.schema.json') {
    copyFileSync(join(fixtures, name), join(copy, name));
  } else {
    symlinkSync(join(fixtures, name), join(copy, name));
  }
}
test.after(() => rmSync(scratch, { recursive: true, force: true }));

function run(dir, args = []) {
  const r = spawnSync(process.execPath, [tool, '--fixtures', dir, ...args], { encoding: 'utf8' });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

// Lints the copy after mutate(doc, schema) has changed parsed copies of the
// two files, and returns the result with the problem lines.
function plant(mutate) {
  for (const name of ['', 'cases.json', 'cases.schema.json']) {
    assert.ok(!lstatSync(join(copy, name)).isSymbolicLink(), `${name || 'the copy'} is a link`);
  }
  const doc = JSON.parse(cases);
  const sch = JSON.parse(schema);
  mutate(doc, sch);
  writeFileSync(join(copy, 'cases.json'), JSON.stringify(doc, null, 2));
  writeFileSync(join(copy, 'cases.schema.json'), JSON.stringify(sch, null, 2));
  const r = run(copy);
  return { ...r, problems: r.err.split('\n').filter((l) => l.startsWith('  - ')).map((l) => l.slice(4)) };
}

const original = JSON.parse(cases);
const indexOf = (pick) => {
  const index = original.cases.findIndex(pick);
  assert.ok(index >= 0, 'no case to plant in');
  return index;
};
// The line lint-cases prints for a schema problem in a case.
const at = (index, path, message) =>
  `case #${index} "${original.cases[index].id}": /cases/${index}${path} ${message}`;
const firstFixture = Object.keys(original.fixtures)[0];

const withMaxMillis = indexOf((c) => c.maxMillis !== undefined);
const okReceipt = indexOf((c) => c.operation === 'verifyReceipt' && c.expected.status === 'ok');
const defaultRoots = indexOf((c) => c.config?.trustedRoots?.source === 'defaults');
const endpoint = indexOf((c) => c.expected?.fields?.['/status'] !== undefined);
const errorCase = indexOf((c) => c.expected?.status === 'error' && c.fault !== undefined);
const withMessageRule = indexOf((c) => c.expected?.messageMustNotContain !== undefined);

// [what is planted, the plant, the problem lines lint-cases must print]
const table = [
  ['a missing required property',
    (d) => { delete d.cases[0].description; },
    [at(0, '', "must have required property 'description'")]],
  ['a wrong type',
    (d) => { d.cases[withMaxMillis].maxMillis = '100'; },
    [at(withMaxMillis, '/maxMillis', 'must be integer, got "100"')]],
  ['an unknown property where additionalProperties is false',
    (d) => { d.cases[0].bogus = 1; },
    [at(0, '', 'must NOT have additional properties: "bogus"')]],
  ['a value outside an enum',
    (d) => { d.fixtures[firstFixture].role = 'inputs'; },
    [`cases.json: /fixtures/${firstFixture}/role must be equal to one of the allowed values `
      + '"input", "trust-anchor", "support", got "inputs"']],
  ['an ok receipt case without environment (expected is a oneOf of three shapes)',
    (d) => { delete d.cases[okReceipt].expected.environment; },
    [at(okReceipt, '/expected', "must have required property 'environment'")]],
  ['a trustedRoots matching no shape of its oneOf',
    (d) => { d.cases[defaultRoots].config.trustedRoots.source = 'bundled'; },
    [at(defaultRoots, '/config/trustedRoots/source', 'must be equal to constant "defaults", got "bundled"')]],
  ['a fixture key outside the id pattern (propertyNames)',
    (d) => { d.fixtures.Bad_Key = d.fixtures[firstFixture]; },
    ['cases.json: /fixtures property name "Bad_Key" must match pattern "^[a-z0-9]+(-[a-z0-9]+)*$"']],
  ['a fields key that is not a JSON pointer (propertyNames)',
    (d) => { d.cases[endpoint].expected.fields.status = 0; },
    [at(endpoint, '/expected/fields', 'property name "status" must match pattern "^(/([^/~]|~[01])*)+$"')]],
  ['an error case without fault (if/then)',
    (d) => { delete d.cases[errorCase].fault; },
    [at(errorCase, '', "must have required property 'fault'")]],
  ['an empty tags list (minItems)',
    (d) => { d.cases[1].tags = []; },
    [at(1, '/tags', 'must NOT have fewer than 1 items')]],
  ['a wrong schemaVersion (const)',
    (d) => { d.schemaVersion = 3; },
    ['cases.json: /schemaVersion must be equal to constant 2, got 3']],
  ['an endpoint /status outside its enum (inside an allOf)',
    (d) => { d.cases[endpoint].expected.fields['/status'] = 21004; },
    [at(endpoint, '/expected/fields/~1status',
      'must be equal to one of the allowed values 0, 21002, 21003, 21007, 21008, 21009, got 21004')]],
  ['a code point above the maximum',
    (d) => { d.cases[withMessageRule].expected.messageMustNotContain.push(1114112); },
    [at(withMessageRule,
      `/expected/messageMustNotContain/${original.cases[withMessageRule].expected.messageMustNotContain.length}`,
      'must be <= 1114111')]],
  ['two problems in one case and one in another',
    (d) => { delete d.cases[0].description; d.cases[0].bogus = 1; d.cases[4].tags = []; },
    [at(0, '', "must have required property 'description'"),
      at(0, '', 'must NOT have additional properties: "bogus"'),
      at(4, '/tags', 'must NOT have fewer than 1 items')]],
  ['a value longer than 80 characters, quoted cut short',
    (d) => { d.cases[0].description = Array(100).fill(1); },
    [at(0, '/description', `must be string, got [${'1,'.repeat(38)}...`)]],
];

for (const [what, mutate, expected] of table) {
  test(`${what}: one line per problem`, () => {
    const r = plant(mutate);
    assert.equal(r.code, 1, r.err);
    assert.deepEqual(r.problems, expected);
  });
}

test('a contentSha256 outside its pattern is reported, and so is the drift', () => {
  const r = plant((d) => {
    const f = d.fixtures[firstFixture];
    f.contentSha256 = f.contentSha256.toUpperCase();
  });
  assert.equal(r.code, 1, r.err);
  assert.equal(r.problems.length, 2, r.err);
  assert.match(r.problems[0], new RegExp(`^cases\\.json: /fixtures/${firstFixture}/contentSha256 must match pattern`));
  assert.match(r.problems[1], new RegExp(`^fixture "${firstFixture}" .* has drifted`));
});

// The schema's own oneOfs are exclusive, so ambiguity needs a schema edit:
// any object now matches the second trustedRoots shape too.
test('a value matching two shapes of a oneOf is reported as ambiguous', () => {
  const r = plant((d, s) => { s.$defs.trustedRoots.oneOf[1] = { type: 'object' }; });
  assert.equal(r.code, 1, r.err);
  const expected = original.cases.flatMap((c, i) => (c.config?.trustedRoots?.source === 'defaults'
    ? [at(i, '/config/trustedRoots', 'matches 2 allowed shapes at once (oneOf branches 0, 1)')] : []));
  assert.deepEqual(r.problems, expected);
});

// A keyword beside a failed oneOf reports on its own; only the oneOf's
// branch errors give way to the closest branch.
test('an error beside a failed oneOf is kept', () => {
  const r = plant((d, s) => {
    s.$defs.case.maxProperties = 3;
    d.cases[0].bogus = 1;
  });
  assert.equal(r.code, 1, r.err);
  assert.deepEqual(r.problems.filter((l) => l.startsWith('case #0 ')), [
    at(0, '', 'must NOT have additional properties: "bogus"'),
    at(0, '', 'must NOT have more than 3 properties'),
  ]);
});

test('a typo keyword in the schema fails strict mode rather than validating everything', () => {
  const r = plant((d, s) => { s.$defs.tags.minItem = 1; });
  assert.equal(r.code, 1, r.err);
  assert.deepEqual(r.problems,
    ['schema: the schema itself could not be applied — strict mode: unknown keyword: "minItem"']);
});

test('the repository fixtures pass', () => {
  const r = run(fixtures);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /lint-cases: OK — \d+ cases over \d+ registered fixtures\./);
});

test('without ajv installed it says to run npm ci and exits 2', () => {
  const tools = join(scratch, 'no-ajv', 'tools');
  mkdirSync(join(tools, 'lib'), { recursive: true });
  copyFileSync(tool, join(tools, 'lint-cases.mjs'));
  copyFileSync(fileURLToPath(new URL('../lib/fixtures.mjs', import.meta.url)), join(tools, 'lib', 'fixtures.mjs'));
  const r = spawnSync(process.execPath, [join(tools, 'lint-cases.mjs'), '--fixtures', fixtures],
    { encoding: 'utf8' });
  assert.equal(r.status, 2, r.stderr);
  assert.match(r.stderr, /run `npm ci --prefix tools` first/);
});

test('usage errors exit 2', () => {
  assert.equal(run(fixtures, ['--nope']).code, 2);
});
