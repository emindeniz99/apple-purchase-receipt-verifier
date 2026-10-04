// With allErrors off, does Ajv report few enough errors that capping a
// failed oneOf's errors to one branch gives one line per problem? Prints
// Ajv's raw errors for each plant, then what is left after keeping only
// the errors at the deepest instance path (the closest a filter can come
// to "the closest branch" without validating again, since an error's
// schemaPath after a $ref does not say which branch it came from). The
// last plant breaks two cases, to show where Ajv stops.
//
//   node all-errors-off-trial.mjs <repo>
//
// Uses the ajv that `npm ci --prefix tools` installs.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { plants, strict } from './plants.mjs';

const [repo] = process.argv.slice(2);
const require = createRequire(join(repo, 'tools/package.json'));
const Ajv2020 = require('ajv/dist/2020.js');

const schema = JSON.parse(readFileSync(join(repo, 'fixtures/cases.schema.json'), 'utf8'));
const cases = readFileSync(join(repo, 'fixtures/cases.json'), 'utf8');
const validate = new Ajv2020({ ...strict, allErrors: false }).compile(schema);

const all = {
  ...plants,
  'two-cases-broken': (doc) => { doc.cases[0].bogus = 1; doc.cases[5].tags = []; },
};
const show = (e) => `${e.instancePath} ${e.message} ${JSON.stringify(e.params)}`;
for (const [name, plant] of Object.entries(all)) {
  const doc = JSON.parse(cases);
  plant(doc);
  validate(doc);
  const leaves = validate.errors.filter((e) => e.keyword !== 'oneOf' && e.keyword !== 'if');
  const depth = Math.max(...leaves.map((e) => e.instancePath.split('/').length));
  const deepest = leaves.filter((e) => e.instancePath.split('/').length === depth);
  console.log(`${name}: ajv ${validate.errors.length} errors, ${deepest.length} at the deepest path`);
  for (const e of validate.errors) console.log(`  raw     ${show(e)}`);
  for (const e of deepest) console.log(`  deepest ${show(e)}`);
}
