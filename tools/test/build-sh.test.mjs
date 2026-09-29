// Tests for rust/bindings/abi/build.sh that build nothing: each run stops
// at a check before cargo starts, in well under a second. They hold the
// compiler pin (the build refuses a compiler other than the channel
// rust/rust-toolchain.toml names, whichever way cargo would find it) and
// the cleanup (a build that stops leaves no earlier run's module behind).
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const buildSh = fileURLToPath(new URL('../../rust/bindings/abi/build.sh', import.meta.url));
const toolchain = readFileSync(new URL('../../rust/rust-toolchain.toml', import.meta.url), 'utf8');
const channel = /^channel *= *"([^"]*)"/m.exec(toolchain)[1];
const OUTPUTS = ['aprv.wasm', 'aprv.component.wasm', 'aprv.wit', 'SHA256SUMS'];

/** A directory of stand-in tools: every tool build.sh looks for, each
 * answering `--version` with `version`; `rustc` also as `other-rustc`,
 * which answers with `otherVersion`. */
function fakeTools(version, otherVersion = '0.0.0') {
  const dir = mkdtempSync(join(tmpdir(), 'build-sh-tools-'));
  const tool = (name, answer) => {
    writeFileSync(join(dir, name), `#!/bin/sh\necho "${answer}"\n`);
    chmodSync(join(dir, name), 0o755);
  };
  tool('rustc', `rustc ${version} (fake)`);
  tool('other-rustc', `rustc ${otherVersion} (fake)`);
  for (const name of ['cargo', 'wasm-tools', 'wit-bindgen']) tool(name, `${name} (fake)`);
  return dir;
}

/** An output directory holding an earlier run's four files. */
function staleOut() {
  const out = mkdtempSync(join(tmpdir(), 'build-sh-out-'));
  for (const name of OUTPUTS) writeFileSync(join(out, name), 'stale\n');
  return out;
}

function run(out, tools, extraEnv = {}) {
  const env = {
    PATH: `${tools}:${process.env.PATH}`,
    HOME: process.env.HOME ?? tmpdir(),
    WASI_SDK_DIR: join(tools, 'no-wasi-sdk'),
    OPENSSL_WASM_DIR: join(tools, 'no-openssl'),
    ...extraEnv,
  };
  for (const [key, value] of Object.entries(env)) if (value === undefined) delete env[key];
  const r = spawnSync('bash', [buildSh, out], { encoding: 'utf8', env, timeout: 30_000 });
  return { code: r.status, err: r.stderr };
}

function assertNoOutputs(out) {
  for (const name of OUTPUTS) assert.equal(existsSync(join(out, name)), false, `${name} stayed behind`);
}

function cleanup(...dirs) {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
}

test('a rustc on PATH other than the pinned channel stops the build, and no earlier output stays', () => {
  const tools = fakeTools('0.0.0');
  const out = staleOut();
  try {
    const r = run(out, tools);
    assert.equal(r.code, 1, r.err);
    assert.match(r.err, new RegExp(`is rustc 0\\.0\\.0 \\(fake\\), not the pinned ${channel.replace(/\./g, '\\.')}`));
    assertNoOutputs(out);
  } finally {
    cleanup(tools, out);
  }
});

test('RUSTC and CARGO_BUILD_RUSTC name the compiler that is checked, not the rustc on PATH', () => {
  const tools = fakeTools(channel, '0.0.0');
  const out = staleOut();
  try {
    for (const variable of ['RUSTC', 'CARGO_BUILD_RUSTC']) {
      const r = run(out, tools, { [variable]: join(tools, 'other-rustc') });
      assert.equal(r.code, 1, r.err);
      assert.match(r.err, /other-rustc is rustc 0\.0\.0 \(fake\), not the pinned/);
      assertNoOutputs(out);
    }
  } finally {
    cleanup(tools, out);
  }
});

test('a compiler wrapper is refused, whichever variable sets it', () => {
  const tools = fakeTools(channel);
  const out = staleOut();
  try {
    for (const variable of ['RUSTC_WRAPPER', 'CARGO_BUILD_RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER',
      'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER']) {
      const r = run(out, tools, { [variable]: '/bin/true' });
      assert.equal(r.code, 1, r.err);
      assert.match(r.err, new RegExp(`${variable} is set`));
      assertNoOutputs(out);
    }
  } finally {
    cleanup(tools, out);
  }
});

test('a missing toolchain directory stops the build after the cleanup, not before it', () => {
  const tools = fakeTools(channel);
  const out = staleOut();
  try {
    const r = run(out, tools, { WASI_SDK_DIR: undefined });
    assert.notEqual(r.code, 0, r.err);
    assert.match(r.err, /WASI_SDK_DIR/);
    assertNoOutputs(out);
  } finally {
    cleanup(tools, out);
  }
});
