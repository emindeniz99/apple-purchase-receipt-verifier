#!/usr/bin/env node
// The licence texts of the third-party code compiled into aprv.wasm
// (OpenSSL, wasi-libc with the musl and cloudlibc parts it carries, the
// Rust standard library) have one source, licenses/wasm/ (OD-11 in
// docs/rust-core/STATUS.md). Each package that ships the module ships a
// copy of them, because its packaging cannot reach outside its directory;
// this diffs every copy against the source, the same way
// tools/check-cert-copies.mjs guards the copies of certs/.
//
//   node tools/check-licence-copies.mjs
//
// A copy must hold every source file, byte for byte, under the name its
// layout gives it, and nothing else but the files listed as its own (Ruby's
// NOTICE, which says what the gem's module contains). Exits 1 on any
// difference, naming the file.
import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SOURCE = 'licenses/wasm';

// Ruby keeps one directory per component; everyone else the flat names.
const flat = (name) => name;
const nested = (name) => {
  if (name === 'musl-COPYRIGHT') return 'wasi-libc/musl-COPYRIGHT';
  if (name === 'wasi-libc-cloudlibc-LICENSE') return 'wasi-libc/cloudlibc-LICENSE';
  const m = /^(openssl|rust|wasi-libc)-(.+)$/.exec(name);
  if (!m) throw new Error(`check-licence-copies: no Ruby name for ${name}`);
  return `${m[1]}/${m[2]}`;
};

const COPIES = [
  { dir: 'node/licenses', name: flat, own: [] },
  { dir: 'dotnet/licenses', name: flat, own: [] },
  { dir: 'swift/Sources/ApplePurchaseReceiptVerifier/Resources/licenses', name: flat, own: [] },
  { dir: 'ruby/licenses', name: nested, own: ['NOTICE'] },
];

const sources = readdirSync(join(ROOT, SOURCE)).sort();
if (sources.length === 0) {
  console.error(`check-licence-copies: ${SOURCE} is empty`);
  process.exit(1);
}

let bad = 0;
for (const copy of COPIES) {
  const base = join(ROOT, copy.dir);
  if (!existsSync(base)) {
    console.log(`::error::${copy.dir} is missing; the package ships the module, so it ships these licences`);
    bad++;
    continue;
  }
  const expected = new Set(copy.own);
  for (const name of sources) {
    const target = copy.name(name);
    expected.add(target);
    const path = join(base, target);
    if (!existsSync(path)) {
      console.log(`::error file=${copy.dir}/${target}::missing: copy ${SOURCE}/${name} there`);
      bad++;
    } else if (!readFileSync(path).equals(readFileSync(join(ROOT, SOURCE, name)))) {
      console.log(`::error file=${copy.dir}/${target}::differs from ${SOURCE}/${name}`);
      bad++;
    }
  }
  for (const entry of readdirSync(base, { recursive: true, withFileTypes: true })) {
    const path = join(entry.parentPath, entry.name);
    if (!statSync(path).isFile()) continue;
    const rel = relative(base, path).split('\\').join('/');
    if (!expected.has(rel)) {
      console.log(`::error file=${copy.dir}/${rel}::not in ${SOURCE}; add it there first, or list it as this copy's own`);
      bad++;
    }
  }
  console.log(`${copy.dir}: ${sources.length} licence files checked against ${SOURCE}`);
}
process.exit(bad ? 1 : 0);
