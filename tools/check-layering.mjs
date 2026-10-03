#!/usr/bin/env node
// The layering check of docs/rust-core/SURFACE.md §9, over the rust/
// workspace. It reads `cargo metadata` and the crates' sources, and fails
// when:
//
//   1. the core's graph contains a binding-generator or Wasm-runtime crate
//      (wasm-bindgen*, js-sys, pyo3*, jni*, napi*, wasmtime*, wit-bindgen*,
//      cbindgen, serde_derive, and the generators the plan rejected), or a
//      workspace crate other than aprv-abi depends on wit-bindgen;
//   2. aprv-surface depends on anything but the core, or its graph reaches a
//      crate outside the core's (serde and serde_json included: the core
//      reads JSON with them, the surface must not name them);
//   3. a boundary crate (aprv-abi, rust/ffi) depends on the core, its
//      adapter or OpenSSL directly, instead of through aprv-surface and
//      aprv-wire;
//   4. `unsafe` appears in a crate's code outside aprv-openssl, aprv-abi,
//      rust/ffi and aprv-server, or the core, aprv-surface or aprv-wire
//      lacks `#![forbid(unsafe_code)]`;
//   5. the core has a module named asn1, x509, cms, chain or crypto, or an
//      ASN.1, X.509 or signature crate in its graph (DECISIONS.md R21);
//   6. `ASN1_get_object`, OpenSSL's TLV header decoder, appears in the
//      core's code, or in the adapter's code outside the header walk
//      rust/openssl/README.md names (src/walk.rs, which decodes no value;
//      src/sys.rs may only declare it).
//
// "Graph" means what `cargo tree -e normal,build` resolves for one package
// on each target the project ships (Linux, macOS and Windows on x86_64 and
// arm64, and wasm32-wasip1): what a build of that package links, without
// the dev-dependencies (a test's schema validator) and without the
// never-true `cfg(any())` entries some crates carry only to pin versions.
//
//   node tools/check-layering.mjs [--rust-dir <dir>]
//
// <dir> defaults to rust/ beside this script. Exit 0 when every rule holds,
// 1 with each violation named, 2 on a usage or cargo error. Needs cargo on
// PATH; tools/test/check-layering.test.mjs plants one violation of each
// rule in a copy of the tree and requires a failure.
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const CORE = 'apple-purchase-receipt-verifier';
const ADAPTER = 'aprv-openssl';
const SURFACE = 'aprv-surface';
const WIRE = 'aprv-wire';
const ABI = 'aprv-abi';
const FFI = 'apple-purchase-receipt-verifier-ffi';
const SERVER = 'aprv-server';

// Rule 1: binding generators and Wasm runtimes (SURFACE.md §9, and the
// generators of DECISIONS.md's rejected table: UniFFI, jni-rs, napi-rs,
// wasm-bindgen, with the other common Rust binding generators beside them).
const GENERATORS = [
  /^wasm-bindgen/, /^js-sys$/, /^web-sys$/, /^pyo3/, /^jni/, /^napi/, /^wasmtime/, /^wit-bindgen/,
  /^wit-component$/, /^cbindgen$/, /^serde_derive$/, /^uniffi/, /^diplomat/, /^cxx/, /^swift-bridge/,
  /^interoptopus/, /^safer-ffi/, /^rustler/, /^magnus$/, /^rb-sys/, /^neon$/, /^wasmer/, /^wasmi/,
];
// Rule 5: ASN.1, X.509, CMS and signature crates. OpenSSL, through the
// adapter, is the substrate (R21); none of these may come back.
const PARSERS = [
  /^asn1/, /^der$/, /^der-parser$/, /^der_derive$/, /^simple_asn1$/, /^yasna$/, /^rasn/, /^bcder$/,
  /^x509/, /^cms$/, /^pkcs\d+$/, /^spki$/, /^sec1$/, /^signature$/, /^ecdsa$/, /^elliptic-curve$/,
  /^p256$/, /^p384$/, /^p521$/, /^k256$/, /^rsa$/, /^ed25519/, /^ring$/, /^aws-lc/, /^rustls-webpki$/,
  /^webpki$/,
];
const FORBIDDEN_MODULES = ['asn1', 'x509', 'cms', 'chain', 'crypto'];
// Rule 6: the header walk, the one adapter file that may call the header
// decoder, and the file that declares it (paths inside the adapter crate).
const HEADER_WALK = 'src/walk.rs';
const DECLARATIONS = 'src/sys.rs';
const MAY_BE_UNSAFE = new Set([ADAPTER, ABI, FFI, SERVER]);
const MUST_FORBID_UNSAFE = [CORE, SURFACE, WIRE];

function usage(message) {
  if (message) console.error(`check-layering: ${message}`);
  console.error('usage: node tools/check-layering.mjs [--rust-dir <dir>]');
  process.exit(2);
}

let args;
try {
  args = parseArgs({ options: { 'rust-dir': { type: 'string', default: join(dirname(fileURLToPath(import.meta.url)), '..', 'rust') } } });
} catch (error) {
  usage(error.message);
}
const rustDir = resolve(args.values['rust-dir']);

const TARGETS = [
  'x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu', 'x86_64-unknown-linux-musl', 'aarch64-unknown-linux-musl',
  'x86_64-apple-darwin', 'aarch64-apple-darwin', 'x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc', 'wasm32-wasip1',
];
const manifest = join(rustDir, 'Cargo.toml');

function cargo(args) {
  try {
    return execFileSync('cargo', args, { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (error) {
    console.error(error.stderr || error.message);
    usage(`cargo ${args[0]} failed`);
  }
}

const metadata = JSON.parse(cargo(['metadata', '--format-version', '1', '--no-deps', '--manifest-path', manifest]));
const members = metadata.packages;
const byName = (name) => members.find((p) => p.name === name);

/** The package names one member declares as normal or build dependencies. */
function shippedDeps(member) {
  return member.dependencies.filter((d) => d.kind === null || d.kind === 'build').map((d) => d.name);
}

const graphs = new Map();
/** Every package name a member's build links, itself included. */
function graph(member) {
  if (!graphs.has(member.name)) {
    const out = cargo([
      'tree', '--manifest-path', manifest, '-p', member.name, '-e', 'normal,build',
      ...TARGETS.flatMap((t) => ['--target', t]), '--prefix', 'none', '--format', '{p}',
    ]);
    graphs.set(member.name, new Set(out.split('\n').filter(Boolean).map((line) => line.split(' ')[0])));
  }
  return graphs.get(member.name);
}

const violations = [];
const fail = (rule, message) => violations.push(`rule ${rule}: ${message}`);

for (const required of [CORE, ADAPTER, SURFACE, WIRE, ABI, FFI]) {
  if (!byName(required)) fail(0, `${required} is not a member of the workspace in ${rustDir}`);
}
if (violations.length) {
  for (const v of violations) console.error(`check-layering: FAIL ${v}`);
  process.exit(1);
}
const core = byName(CORE);
const coreGraph = graph(core);

// 1. No generator or runtime in the core's graph; wit-bindgen only in aprv-abi.
for (const name of coreGraph) {
  if (GENERATORS.some((re) => re.test(name))) fail(1, `the core's graph contains ${name}, a binding generator or Wasm runtime`);
}
for (const member of members) {
  if (member.name === ABI) continue;
  for (const name of graph(member)) {
    if (/^wit-bindgen/.test(name)) fail(1, `${member.name} reaches ${name}; wit-bindgen belongs to ${ABI} alone`);
  }
}

// 2. The surface: the core only.
const surface = byName(SURFACE);
for (const dep of shippedDeps(surface)) {
  if (dep !== CORE) fail(2, `${SURFACE} depends on ${dep}; it depends on the core only`);
}
for (const name of graph(surface)) {
  if (name !== SURFACE && !coreGraph.has(name)) fail(2, `${SURFACE}'s graph reaches ${name}, outside the core's`);
}

// 3. The boundary crates reach the core through the surface and the wire.
for (const boundary of [ABI, FFI]) {
  for (const dep of shippedDeps(byName(boundary))) {
    if ([CORE, ADAPTER, 'openssl', 'openssl-sys'].includes(dep)) {
      fail(3, `${boundary} depends on ${dep} directly; it reaches the core through ${SURFACE} and ${WIRE}`);
    }
  }
}

// 4. unsafe only at the edges.
/** Rust source with comments, strings and character literals blanked. */
function code(text) {
  let out = '';
  let i = 0;
  while (i < text.length) {
    const rest = text.slice(i, i + 3);
    if (rest.startsWith('//')) {
      const end = text.indexOf('\n', i);
      i = end < 0 ? text.length : end;
    } else if (rest.startsWith('/*')) {
      let depth = 1;
      i += 2;
      while (i < text.length && depth > 0) {
        if (text.startsWith('/*', i)) { depth++; i += 2; } else if (text.startsWith('*/', i)) { depth--; i += 2; } else i++;
      }
      out += ' ';
    } else if (/^r#*"/.test(text.slice(i, i + 10)) && !/[A-Za-z0-9_]/.test(text[i - 1] ?? '')) {
      const hashes = /^r(#*)"/.exec(text.slice(i))[1];
      const end = text.indexOf(`"${hashes}`, i + 2 + hashes.length);
      i = end < 0 ? text.length : end + 1 + hashes.length;
      out += '""';
    } else if (text[i] === '"') {
      i++;
      while (i < text.length && text[i] !== '"') i += text[i] === '\\' ? 2 : 1;
      i++;
      out += '""';
    } else if (text[i] === "'" && /^'(\\.[^']*|[^\\'])'/.test(text.slice(i, i + 12))) {
      i += /^'(\\.[^']*|[^\\'])'/.exec(text.slice(i, i + 12))[0].length;
      out += "' '";
    } else {
      out += text[i++];
    }
  }
  return out;
}

function rustFiles(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).flatMap((entry) => {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) return rustFiles(path);
    return path.endsWith('.rs') ? [path] : [];
  });
}

/** The directories a member's shipped code lives in: its library, binaries and build script. */
function sourceRoots(member) {
  const root = dirname(member.manifest_path);
  const dirs = new Set();
  for (const target of member.targets) {
    if (target.kind.some((k) => ['lib', 'cdylib', 'staticlib', 'rlib', 'bin', 'custom-build', 'proc-macro'].includes(k))) {
      dirs.add(dirname(target.src_path));
    }
  }
  return [...dirs].filter((d) => d.startsWith(root));
}

for (const member of members) {
  if (MAY_BE_UNSAFE.has(member.name)) continue;
  for (const dir of sourceRoots(member)) {
    for (const file of rustFiles(dir)) {
      if (/\bunsafe\b/.test(code(readFileSync(file, 'utf8')))) {
        fail(4, `${relative(rustDir, file)} (${member.name}) uses unsafe; unsafe belongs to ${[...MAY_BE_UNSAFE].join(', ')}`);
      }
    }
  }
}
for (const name of MUST_FORBID_UNSAFE) {
  const member = byName(name);
  const lib = member.targets.find((t) => t.kind.includes('lib') || t.kind.includes('rlib'));
  if (!lib || !/#!\[forbid\(unsafe_code\)\]/.test(code(readFileSync(lib.src_path, 'utf8')))) {
    fail(4, `${name} must carry #![forbid(unsafe_code)] in ${lib ? relative(rustDir, lib.src_path) : 'its library'}`);
  }
}

// 5. No hand-written ASN.1, X.509, CMS or signature code in the core.
const coreSrc = join(dirname(core.manifest_path), 'src');
for (const module of FORBIDDEN_MODULES) {
  if (existsSync(join(coreSrc, `${module}.rs`)) || existsSync(join(coreSrc, module))) {
    fail(5, `the core has a module file named ${module} (${relative(rustDir, join(coreSrc, module))})`);
  }
}
for (const file of rustFiles(coreSrc)) {
  for (const match of code(readFileSync(file, 'utf8')).matchAll(/\bmod\s+([A-Za-z_][A-Za-z0-9_]*)/g)) {
    if (FORBIDDEN_MODULES.includes(match[1])) fail(5, `${relative(rustDir, file)} declares a module named ${match[1]}`);
  }
}
for (const name of coreGraph) {
  if (PARSERS.some((re) => re.test(name))) fail(5, `the core's graph contains ${name}, an ASN.1, X.509 or signature crate`);
}

// 6. The header decoder only in the adapter's header walk.
/** C source with comments blanked. */
function cCode(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/\/\/[^\n]*/g, ' ');
}
for (const file of rustFiles(coreSrc)) {
  if (/\bASN1_get_object\b/.test(code(readFileSync(file, 'utf8')))) {
    fail(6, `${relative(rustDir, file)} names ASN1_get_object; the core reads no ASN.1 header itself`);
  }
}
const adapterDir = dirname(byName(ADAPTER).manifest_path);
const adapterFiles = [
  ...rustFiles(join(adapterDir, 'src')),
  ...readdirSync(adapterDir).filter((f) => f.endsWith('.c') || f.endsWith('.h')).map((f) => join(adapterDir, f)),
];
for (const file of adapterFiles) {
  const inside = relative(adapterDir, file).split('\\').join('/');
  if (inside === HEADER_WALK) continue;
  const text = file.endsWith('.rs') ? code(readFileSync(file, 'utf8')) : cCode(readFileSync(file, 'utf8'));
  for (const match of text.matchAll(/(\bfn\s+)?\bASN1_get_object\b/g)) {
    if (inside === DECLARATIONS && match[1]) continue;
    fail(6, `${relative(rustDir, file)} calls ASN1_get_object outside the header walk (${HEADER_WALK})`);
  }
}

if (violations.length) {
  for (const v of violations) console.error(`check-layering: FAIL ${v}`);
  process.exit(1);
}
console.log(
  `check-layering: ok, 6 rules over ${members.length} workspace members; the core ships with ${coreGraph.size} packages: ${[...coreGraph].sort().join(', ')}`,
);
