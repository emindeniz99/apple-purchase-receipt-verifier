// Does @apideck/better-ajv-errors turn Ajv's errors for one planted
// violation into one readable line? Runs each plant with allErrors on and
// off and prints how many errors Ajv gave, how many lines the formatter
// made of them, and the lines, or the formatter's exception.
//
//   node better-ajv-errors-trial.mjs <repo> <scratch>
//
// <scratch> holds node_modules with ajv and @apideck/better-ajv-errors
// (README.md has the install command).
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { plants, strict } from './plants.mjs';

const [repo, scratch] = process.argv.slice(2);
const require = createRequire(join(scratch, 'package.json'));
const Ajv2020 = require('ajv/dist/2020.js');
const { betterAjvErrors } = require('@apideck/better-ajv-errors');

const schema = JSON.parse(readFileSync(join(repo, 'fixtures/cases.schema.json'), 'utf8'));
const cases = readFileSync(join(repo, 'fixtures/cases.json'), 'utf8');

for (const allErrors of [true, false]) {
  console.log(`=== allErrors: ${allErrors}`);
  const validate = new Ajv2020({ ...strict, allErrors }).compile(schema);
  for (const [name, plant] of Object.entries(plants)) {
    const doc = JSON.parse(cases);
    plant(doc);
    validate(doc);
    let lines;
    try {
      lines = betterAjvErrors({ schema, data: doc, errors: validate.errors, basePath: 'cases.json' });
    } catch (error) {
      console.log(`${name}: ajv ${validate.errors.length} errors -> threw ${error.constructor.name}: ${error.message}`);
      continue;
    }
    console.log(`${name}: ajv ${validate.errors.length} errors -> ${lines.length} lines`);
    for (const line of lines) console.log(`  ${line.path} | ${line.message}`);
  }
}
