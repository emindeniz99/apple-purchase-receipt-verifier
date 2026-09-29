#!/usr/bin/env node
// Validates a JSONL file of wire answers against a JSON Schema 2020-12 file,
// and exits non-zero on the first answer that does not validate.
//
//   node tools/validate-wire.mjs <schema.json> <answers.jsonl> [--field <name>]
//
// Every *.json file beside <schema.json> is registered first, so a $ref from
// one wire schema to another (rust/bindings/wire/schema/) resolves offline.
// Each non-empty line of <answers.jsonl> is one answer:
//
//   - without --field, the line IS the answer JSON (what aprv.wasm returned);
//   - with --field, the line is a row object and the answer is row[<name>],
//     either a JSON value or a string holding the answer's JSON text (the
//     trap host's {"id", "out"} rows). A row without that field fails.
//
// `format` is an annotation, as JSON Schema 2020-12 defines it by default;
// every other keyword is enforced, and an unknown keyword in a schema is an
// error (Ajv's strict mode), so a typo cannot silently validate everything.
//
// Needs `npm ci --prefix tools` (ajv, pinned in tools/package-lock.json).
import { readFileSync, readdirSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const Ajv2020 = require('ajv/dist/2020.js');

function usage(message) {
  if (message) console.error(`validate-wire: ${message}`);
  console.error('usage: node tools/validate-wire.mjs <schema.json> <answers.jsonl> [--field <name>]');
  process.exit(2);
}

const args = process.argv.slice(2);
let field;
const positional = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--field') {
    field = args[++i];
    if (!field) usage('--field needs a name');
  } else if (args[i].startsWith('--')) {
    usage(`unknown option ${args[i]}`);
  } else {
    positional.push(args[i]);
  }
}
if (positional.length !== 2) usage();
const [schemaPath, answersPath] = positional.map((p) => resolve(p));

const ajv = new Ajv2020({ strict: true, allErrors: true, validateFormats: false });
const schemaDir = dirname(schemaPath);
let target;
for (const name of readdirSync(schemaDir).filter((n) => n.endsWith('.json')).sort()) {
  const path = join(schemaDir, name);
  let schema;
  try {
    schema = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    console.error(`validate-wire: ${name} is not JSON: ${error.message}`);
    process.exit(2);
  }
  // The file name is the key, so a $ref by relative file name resolves even
  // when a schema carries no $id.
  ajv.addSchema(schema, schema.$id ?? name);
  if (path === schemaPath) target = schema.$id ?? name;
}
if (target === undefined) usage(`${schemaPath} is not a .json file in ${schemaDir}`);

let validate;
try {
  validate = ajv.getSchema(target);
} catch (error) {
  console.error(`validate-wire: ${basename(schemaPath)} does not compile: ${error.message}`);
  process.exit(2);
}

const lines = readFileSync(answersPath, 'utf8').split('\n');
let count = 0;
for (let n = 0; n < lines.length; n++) {
  const line = lines[n];
  if (line.trim() === '') continue;
  const where = `${basename(answersPath)}:${n + 1}`;
  let answer;
  let id;
  try {
    const parsed = JSON.parse(line);
    if (field === undefined) {
      answer = parsed;
    } else {
      id = parsed?.id;
      if (parsed === null || typeof parsed !== 'object' || !(field in parsed)) {
        throw new Error(`the row has no "${field}" field`);
      }
      answer = typeof parsed[field] === 'string' ? JSON.parse(parsed[field]) : parsed[field];
    }
  } catch (error) {
    console.error(`validate-wire: ${where}${id ? ` (${id})` : ''}: not an answer: ${error.message}`);
    process.exit(1);
  }
  if (!validate(answer)) {
    console.error(`validate-wire: ${where}${id ? ` (${id})` : ''} does not validate against ${basename(schemaPath)}:`);
    for (const e of validate.errors) {
      console.error(`  ${e.instancePath || '/'} ${e.message} (${e.schemaPath})`);
    }
    console.error(`  answer: ${JSON.stringify(answer).slice(0, 400)}`);
    process.exit(1);
  }
  count++;
}
if (count === 0) {
  console.error(`validate-wire: ${basename(answersPath)} holds no answers; an empty file proves nothing`);
  process.exit(1);
}
console.log(`validate-wire: ${count} answers in ${basename(answersPath)} validate against ${basename(schemaPath)}`);
