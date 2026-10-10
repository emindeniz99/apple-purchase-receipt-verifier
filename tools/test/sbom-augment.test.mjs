// Tests for tools/sbom-augment.mjs. The wasm kind reads this repository's
// real pins (tools/wasm-toolchain.sh, rust/rust-toolchain.toml); the server
// kind reads a fixture tree through APRV_REPO_ROOT, since rust/Cargo.lock
// only gains wasmtime when aprv-server joins the workspace.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const tool = fileURLToPath(new URL('../sbom-augment.mjs', import.meta.url));
const fx = (p) => fileURLToPath(new URL(`fixtures/sbom/${p}`, import.meta.url));
const pins = readFileSync(fileURLToPath(new URL('../wasm-toolchain.sh', import.meta.url)), 'utf8');
const pin = (name) => new RegExp(`^${name}=(\\S+)$`, 'm').exec(pins)[1];
const tmp = mkdtempSync(join(tmpdir(), 'sbom-augment-'));

function run(args, env = {}) {
  const r = spawnSync(process.execPath, [tool, ...args], { encoding: 'utf8', env: { ...process.env, ...env } });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

test('wasm: adds OpenSSL, wasi-libc, wasi-sdk, rustc, wit-bindgen and wasm-tools from the pins', () => {
  const out = join(tmp, 'wasm.cdx.json');
  const r = run(['augment', '--kind', 'wasm', '--in', fx('cargo.cdx.json'), '--out', out,
    '--artifact', fx('artifact.bin'), '--wasi-sdk-dir', fx('wasi-sdk'), '--rustc-vv', fx('rustc-vv.txt')]);
  assert.equal(r.code, 0, r.err);
  const sbom = JSON.parse(readFileSync(out, 'utf8'));
  const by = (name) => sbom.components.find((c) => c.name === name);
  assert.equal(by('OpenSSL').version, pin('OPENSSL_VERSION'));
  assert.equal(by('OpenSSL').hashes[0].content, pin('OPENSSL_SHA256'));
  assert.equal(by('OpenSSL').scope, 'required');
  assert.equal(by('wasi-sdk').hashes[0].content, pin('WASI_SDK_SHA256'));
  assert.equal(by('wasi-sdk').scope, 'excluded');
  assert.equal(by('wasi-libc').version, '2e6fb9d8ee0c');
  assert.equal(by('wit-bindgen-cli').version, pin('WIT_BINDGEN_VERSION'));
  assert.equal(by('wasm-tools').version, pin('WASM_TOOLS_VERSION'));
  assert.ok(by('rustc').properties.some((p) => p.value === '48a229ceaefd4985c50990b14116b6d856af0985'));
  assert.ok(by('openssl-sys'), 'the Cargo components stay');
  const hash = createHash('sha256').update(readFileSync(fx('artifact.bin'))).digest('hex');
  assert.deepEqual(sbom.metadata.component.hashes, [{ alg: 'SHA-256', content: hash }]);
  const root = sbom.dependencies.find((d) => d.ref === sbom.metadata.component['bom-ref']);
  assert.ok(root.dependsOn.includes('aprv-build:openssl') && root.dependsOn.includes('aprv-build:wasi-libc'));
  assert.ok(!root.dependsOn.includes('aprv-build:wasi-sdk'), 'a build tool is not a dependency of the artifact');

  const again = run(['check', '--kind', 'wasm', out]);
  assert.equal(again.code, 0, again.err);
});

test('check fails when a pinned version is missing or different', () => {
  const out = join(tmp, 'wasm.cdx.json');
  const sbom = JSON.parse(readFileSync(out, 'utf8'));
  sbom.components.find((c) => c.name === 'OpenSSL').version = '3.5.0';
  sbom.components = sbom.components.filter((c) => c.name !== 'wit-bindgen-cli');
  const bad = join(tmp, 'bad.cdx.json');
  writeFileSync(bad, JSON.stringify(sbom));
  const r = run(['check', '--kind', 'wasm', bad]);
  assert.equal(r.code, 1);
  assert.ok(r.err.includes(`OpenSSL is 3.5.0, the pin is ${pin('OPENSSL_VERSION')}`), r.err);
  assert.match(r.err, /names no wit-bindgen-cli/);
});

test('check fails on an SBOM with no artifact hash', () => {
  const r = run(['check', '--kind', 'wasm', fx('cargo.cdx.json')]);
  assert.equal(r.code, 1);
  assert.match(r.err, /no SHA-256 of the artifact/);
});

test('a rustc that is not the pinned release is refused', () => {
  const r = run(['augment', '--kind', 'wasm', '--in', fx('cargo.cdx.json'), '--out', join(tmp, 'x.json'),
    '--artifact', fx('artifact.bin'), '--wasi-sdk-dir', fx('wasi-sdk'), '--rustc-vv', fx('rustc-vv-wrong.txt')]);
  assert.equal(r.code, 1);
  assert.match(r.err, /release 1\.97\.0, rust\/rust-toolchain\.toml pins 1\.98\.1/);
});

test('server: adds wasmtime from Cargo.lock, musl, rustc and the embedded component by hash', () => {
  const out = join(tmp, 'server.cdx.json');
  const env = { APRV_REPO_ROOT: fx('repo') };
  const r = run(['augment', '--kind', 'server', '--in', fx('cargo.cdx.json'), '--out', out,
    '--artifact', fx('artifact.bin'), '--embedded', fx('component.bin')], env);
  assert.equal(r.code, 0, r.err);
  const sbom = JSON.parse(readFileSync(out, 'utf8'));
  const by = (name) => sbom.components.find((c) => c.name === name);
  assert.equal(by('wasmtime').version, '49.0.1');
  assert.equal(by('wasmtime').hashes[0].content, '0000000000000000000000000000000000000000000000000000000000000049');
  assert.equal(by('musl').version, 'rustc-1.98.1');
  const embedded = createHash('sha256').update(readFileSync(fx('component.bin'))).digest('hex');
  assert.equal(by('aprv.component.wasm').hashes[0].content, embedded);
  assert.equal(run(['check', '--kind', 'server', '--embedded', fx('component.bin'), out], env).code, 0);
  assert.equal(run(['check', '--kind', 'server', '--embedded', fx('artifact.bin'), out], env).code, 1, 'another component is refused');
});

test('usage errors exit 2', () => {
  assert.equal(run([]).code, 2);
  assert.equal(run(['augment', '--kind', 'wasm']).code, 2);
  assert.equal(run(['check', '--kind', 'nope', fx('cargo.cdx.json')]).code, 2);
});
