#!/usr/bin/env node
// Completes a CycloneDX SBOM with what Cargo cannot see, and checks that it
// names every pinned version.
//
//   node tools/sbom-augment.mjs augment --kind <wasm|server|java-wasm> --in <sbom.json>
//        --out <sbom.json> --artifact <file> [--wasi-sdk-dir <dir>]
//        [--embedded <component.wasm>] [--rustc-vv <file>]
//   node tools/sbom-augment.mjs check --kind <wasm|server|java-wasm> <sbom.json>
//
// `augment` reads the input SBOM (cargo cyclonedx's for aprv.wasm and the
// server, any CycloneDX JSON for the Java -wasm jar), sets the artifact's
// SHA-256 on metadata.component, adds the components below from the pins,
// then runs `check` on the result and refuses to write an SBOM that fails.
//
// Pins, all read from the repository, never typed here:
//   tools/wasm-toolchain.sh   OpenSSL, wasi-sdk, wasm-tools, wit-bindgen:
//                             version, source URL, archive SHA-256
//   rust/rust-toolchain.toml  rustc's version (--rustc-vv adds the commit
//                             hash from `rustc -vV` and checks the release)
//   <wasi-sdk>/VERSION        wasi-libc's commit inside that wasi-sdk
//   rust/Cargo.lock           wasmtime's version and crate checksum (or
//                             rust/server/Cargo.lock)
//   java-wasm/pom.xml         Endive's version (the endive.version property)
//
// What each kind must name:
//   wasm       OpenSSL (linked in), wasi-libc (linked in), wasi-sdk, rustc,
//              wit-bindgen, wasm-tools (build tools)
//   server     wasmtime (linked in), musl (linked in, the one rustc's musl
//              target ships), rustc, and the embedded component by SHA-256
//   java-wasm  Endive (the compiler and runtime of the jar's classes) and the
//              aprv.wasm it compiled, by SHA-256
//
// Build tools carry scope "excluded": they made the artifact and are not in
// it. Dependency-free (node:fs, node:crypto).
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

// The repository root the pins are read from; APRV_REPO_ROOT points the
// tool's own tests at a fixture tree.
const REPO = process.env.APRV_REPO_ROOT ? `${process.env.APRV_REPO_ROOT.replace(/\/$/, '')}/` : fileURLToPath(new URL('..', import.meta.url));
const sha256 = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');

function fail(message, code = 1) {
  console.error(`sbom-augment: ${message}`);
  process.exit(code);
}

// --- pins -----------------------------------------------------------------

function shellPins() {
  const text = readFileSync(`${REPO}tools/wasm-toolchain.sh`, 'utf8');
  const get = (name) => {
    const m = new RegExp(`^${name}=(\\S+)$`, 'm').exec(text);
    if (!m) fail(`tools/wasm-toolchain.sh pins no ${name}`);
    return m[1];
  };
  const pin = (prefix) => ({ version: get(`${prefix}_VERSION`), url: get(`${prefix}_URL`), sha256: get(`${prefix}_SHA256`) });
  return { openssl: pin('OPENSSL'), wasiSdk: pin('WASI_SDK'), wasmTools: pin('WASM_TOOLS'), witBindgen: pin('WIT_BINDGEN') };
}

function rustcPin() {
  const m = /^channel\s*=\s*"([^"]+)"/m.exec(readFileSync(`${REPO}rust/rust-toolchain.toml`, 'utf8'));
  if (!m) fail('rust/rust-toolchain.toml pins no channel');
  return m[1];
}

// The workspace lockfile, or the server's own if it stays outside the workspace.
function wasmtimePin() {
  const re = /\[\[package\]\]\nname = "wasmtime"\nversion = "([^"]+)"\nsource = "[^"]+"\nchecksum = "([0-9a-f]{64})"/;
  for (const lock of ['rust/Cargo.lock', 'rust/server/Cargo.lock']) {
    if (!existsSync(`${REPO}${lock}`)) continue;
    const m = re.exec(readFileSync(`${REPO}${lock}`, 'utf8'));
    if (m) return { version: m[1], sha256: m[2], lock };
  }
  fail('neither rust/Cargo.lock nor rust/server/Cargo.lock locks wasmtime from a registry');
}

function endivePin() {
  const path = `${REPO}java-wasm/pom.xml`;
  if (!existsSync(path)) fail('java-wasm/pom.xml does not exist');
  const m = /<endive\.version>([^<]+)<\/endive\.version>/.exec(readFileSync(path, 'utf8'));
  if (!m) fail('java-wasm/pom.xml has no <endive.version> property');
  return m[1];
}

function wasiLibcCommit(wasiSdkDir) {
  const m = /^wasi-libc:\s*([0-9a-f]+)$/m.exec(readFileSync(`${wasiSdkDir}/VERSION`, 'utf8'));
  if (!m) fail(`${wasiSdkDir}/VERSION names no wasi-libc commit`);
  return m[1];
}

// --- components --------------------------------------------------------------

const prop = (name, value) => ({ name: `aprv:${name}`, value: String(value) });

function component({ ref, type = 'library', name, version, scope, purl, sha256: hash, url, properties = [], description }) {
  const c = { 'bom-ref': ref, type, name, version };
  if (description) c.description = description;
  if (scope) c.scope = scope;
  if (hash) c.hashes = [{ alg: 'SHA-256', content: hash }];
  if (purl) c.purl = purl;
  if (url) c.externalReferences = [{ type: 'distribution', url }];
  if (properties.length) c.properties = properties;
  return c;
}

function extraComponents(kind, opts) {
  const out = [];
  const rustc = rustcPin();
  const rustcProps = [prop('role', 'build-tool'), prop('pinned-by', 'rust/rust-toolchain.toml')];
  if (opts['rustc-vv']) {
    const vv = readFileSync(opts['rustc-vv'], 'utf8');
    const release = /^release:\s*(\S+)$/m.exec(vv)?.[1];
    const commit = /^commit-hash:\s*([0-9a-f]+)$/m.exec(vv)?.[1];
    if (release !== rustc) fail(`rustc -vV says release ${release}, rust/rust-toolchain.toml pins ${rustc}`);
    if (commit) rustcProps.push(prop('commit-hash', commit));
  }
  const rustcComponent = component({
    ref: 'aprv-build:rustc', type: 'application', name: 'rustc', version: rustc, scope: 'excluded',
    purl: `pkg:generic/rustc@${rustc}`, properties: rustcProps,
    description: 'The Rust compiler and its standard library for the target',
  });
  if (kind === 'wasm') {
    if (!opts['wasi-sdk-dir']) fail('--kind wasm needs --wasi-sdk-dir (wasi-libc is named from its VERSION file)');
    const p = shellPins();
    const pinned = [prop('pinned-by', 'tools/wasm-toolchain.sh')];
    out.push(
      component({ ref: 'aprv-build:openssl', name: 'OpenSSL', version: p.openssl.version, scope: 'required',
        purl: `pkg:generic/openssl@${p.openssl.version}`, sha256: p.openssl.sha256, url: p.openssl.url,
        properties: [prop('role', 'linked'), prop('hash-of', 'source tarball'), ...pinned],
        description: 'libcrypto, compiled for wasm32-wasip1 with no-asm, linked into the module' }),
      component({ ref: 'aprv-build:wasi-libc', name: 'wasi-libc', version: wasiLibcCommit(opts['wasi-sdk-dir']), scope: 'required',
        purl: `pkg:github/WebAssembly/wasi-libc@${wasiLibcCommit(opts['wasi-sdk-dir'])}`,
        properties: [prop('role', 'linked'), prop('shipped-in', `wasi-sdk ${p.wasiSdk.version}`)],
        description: 'The C library linked into the module, as shipped in wasi-sdk (version is its commit)' }),
      component({ ref: 'aprv-build:wasi-sdk', type: 'application', name: 'wasi-sdk', version: p.wasiSdk.version, scope: 'excluded',
        purl: `pkg:github/WebAssembly/wasi-sdk@wasi-sdk-${p.wasiSdk.version.split('.')[0]}`, sha256: p.wasiSdk.sha256, url: p.wasiSdk.url,
        properties: [prop('role', 'build-tool'), prop('hash-of', 'release archive'), ...pinned] }),
      rustcComponent,
      component({ ref: 'aprv-build:wit-bindgen-cli', type: 'application', name: 'wit-bindgen-cli', version: p.witBindgen.version, scope: 'excluded',
        purl: `pkg:github/bytecodealliance/wit-bindgen@v${p.witBindgen.version}`, sha256: p.witBindgen.sha256, url: p.witBindgen.url,
        properties: [prop('role', 'build-tool'), prop('hash-of', 'release archive'), ...pinned] }),
      component({ ref: 'aprv-build:wasm-tools', type: 'application', name: 'wasm-tools', version: p.wasmTools.version, scope: 'excluded',
        purl: `pkg:github/bytecodealliance/wasm-tools@v${p.wasmTools.version}`, sha256: p.wasmTools.sha256, url: p.wasmTools.url,
        properties: [prop('role', 'build-tool'), prop('hash-of', 'release archive'), ...pinned] }),
    );
  } else if (kind === 'server') {
    if (!opts.embedded) fail('--kind server needs --embedded <component.wasm>');
    const w = wasmtimePin();
    out.push(
      component({ ref: 'aprv-build:wasmtime', name: 'wasmtime', version: w.version, scope: 'required',
        purl: `pkg:cargo/wasmtime@${w.version}`, sha256: w.sha256,
        properties: [prop('role', 'linked'), prop('hash-of', 'crate (Cargo.lock checksum)'), prop('pinned-by', w.lock)] }),
      component({ ref: 'aprv-build:musl', name: 'musl', version: `rustc-${rustcPin()}`, scope: 'required',
        purl: 'pkg:generic/musl',
        properties: [prop('role', 'linked'), prop('shipped-in', `the self-contained musl of rustc ${rustcPin()}'s *-unknown-linux-musl targets`)],
        description: 'Linked statically into the Linux builds; its version is the one that rustc release ships' }),
      rustcComponent,
      component({ ref: 'aprv-build:aprv-component', type: 'file', name: 'aprv.component.wasm', version: 'embedded', scope: 'required',
        sha256: sha256(opts.embedded), properties: [prop('role', 'embedded, precompiled at build time')] }),
    );
  } else if (kind === 'java-wasm') {
    if (!opts.embedded) fail('--kind java-wasm needs --embedded <aprv.wasm>');
    const v = endivePin();
    out.push(
      component({ ref: 'aprv-build:endive', type: 'framework', name: 'endive', version: v, scope: 'required',
        purl: `pkg:maven/run.endive/runtime@${v}`,
        properties: [prop('role', 'compiler and runtime of the generated classes'), prop('pinned-by', 'java-wasm/pom.xml')] }),
      component({ ref: 'aprv-build:aprv-wasm', type: 'file', name: 'aprv.wasm', version: 'compiled', scope: 'required',
        sha256: sha256(opts.embedded), properties: [prop('role', 'compiled to JVM classes at build time')] }),
    );
  } else {
    fail(`unknown kind ${kind}`, 2);
  }
  return out;
}

// --- check ---------------------------------------------------------------------

function check(kind, sbom, opts = {}) {
  const problems = [];
  if (sbom.bomFormat !== 'CycloneDX') problems.push('bomFormat is not CycloneDX');
  if (!sbom.metadata?.component?.hashes?.some((h) => h.alg === 'SHA-256' && /^[0-9a-f]{64}$/.test(h.content))) {
    problems.push('metadata.component carries no SHA-256 of the artifact');
  }
  const comps = sbom.components ?? [];
  const find = (name) => comps.filter((c) => c.name === name);
  const want = (name, version, hash) => {
    const hits = find(name);
    if (hits.length === 0) return problems.push(`names no ${name}`);
    if (!hits.some((c) => c.version === version)) problems.push(`${name} is ${hits.map((c) => c.version).join(', ')}, the pin is ${version}`);
    if (hash && !hits.some((c) => c.hashes?.some((h) => h.alg === 'SHA-256' && h.content === hash))) problems.push(`${name} does not carry the pinned SHA-256 ${hash}`);
  };
  const rustc = rustcPin();
  if (kind === 'wasm') {
    const p = shellPins();
    want('OpenSSL', p.openssl.version, p.openssl.sha256);
    want('wasi-sdk', p.wasiSdk.version, p.wasiSdk.sha256);
    want('wit-bindgen-cli', p.witBindgen.version, p.witBindgen.sha256);
    want('wasm-tools', p.wasmTools.version, p.wasmTools.sha256);
    if (find('wasi-libc').length === 0) problems.push('names no wasi-libc');
    want('rustc', rustc);
  } else if (kind === 'server') {
    const w = wasmtimePin();
    want('wasmtime', w.version, w.sha256);
    want('musl', `rustc-${rustc}`);
    want('rustc', rustc);
    if (!find('aprv.component.wasm').some((c) => c.hashes?.length)) problems.push('names no embedded aprv.component.wasm by hash');
    if (opts.embedded) want('aprv.component.wasm', 'embedded', sha256(opts.embedded));
  } else if (kind === 'java-wasm') {
    want('endive', endivePin());
    if (!find('aprv.wasm').some((c) => c.hashes?.length)) problems.push('names no compiled aprv.wasm by hash');
  } else {
    fail(`unknown kind ${kind}`, 2);
  }
  return problems;
}

// --- main ------------------------------------------------------------------------

let args;
try {
  const names = ['kind', 'in', 'out', 'artifact', 'wasi-sdk-dir', 'embedded', 'rustc-vv'];
  args = parseArgs({ allowPositionals: true, options: Object.fromEntries(names.map((name) => [name, { type: 'string' }])) });
} catch (error) {
  fail(error.message, 2);
}
const [mode, ...positional] = args.positionals;
const opts = { ...args.values, positional };
if (!opts.kind) fail('usage: sbom-augment.mjs augment|check --kind <wasm|server|java-wasm> ... (see the header)', 2);

if (mode === 'augment') {
  if (!opts.in || !opts.out || !opts.artifact) fail('augment needs --in, --out and --artifact', 2);
  const sbom = JSON.parse(readFileSync(opts.in, 'utf8'));
  if (sbom.bomFormat !== 'CycloneDX') fail(`${opts.in} is not a CycloneDX JSON document`);
  sbom.metadata ??= {};
  sbom.metadata.component ??= { type: 'application', name: opts.artifact.split('/').pop() };
  sbom.metadata.component.hashes = [
    ...(sbom.metadata.component.hashes ?? []).filter((h) => h.alg !== 'SHA-256'),
    { alg: 'SHA-256', content: sha256(opts.artifact) },
  ];
  const added = extraComponents(opts.kind, opts);
  const refs = new Set(added.map((c) => c['bom-ref']));
  sbom.components = [...(sbom.components ?? []).filter((c) => !refs.has(c['bom-ref'])), ...added];
  const rootRef = sbom.metadata.component['bom-ref'];
  if (rootRef) {
    sbom.dependencies ??= [];
    const root = sbom.dependencies.find((d) => d.ref === rootRef) ?? (sbom.dependencies.push({ ref: rootRef, dependsOn: [] }), sbom.dependencies.at(-1));
    root.dependsOn = [...new Set([...(root.dependsOn ?? []), ...added.filter((c) => c.scope === 'required').map((c) => c['bom-ref'])])];
  }
  const problems = check(opts.kind, sbom, opts);
  if (problems.length) fail(`the augmented SBOM fails its own check:\n  ${problems.join('\n  ')}`);
  writeFileSync(opts.out, `${JSON.stringify(sbom, null, 2)}\n`);
  console.log(`sbom-augment: ${opts.out}: ${opts.kind} SBOM with ${sbom.components.length} components; ${added.map((c) => `${c.name} ${c.version}`).join(', ')}`);
} else if (mode === 'check') {
  if (opts.positional.length !== 1) fail('check takes one SBOM file', 2);
  const problems = check(opts.kind, JSON.parse(readFileSync(opts.positional[0], 'utf8')), opts);
  if (problems.length) fail(`${opts.positional[0]}:\n  ${problems.join('\n  ')}`);
  console.log(`sbom-augment: ${opts.positional[0]} names every pinned version for ${opts.kind}`);
} else {
  fail(`unknown mode ${mode}`, 2);
}
