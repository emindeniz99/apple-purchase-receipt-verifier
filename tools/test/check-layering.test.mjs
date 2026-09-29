// tools/check-layering.mjs against the real rust/ workspace, and against a
// copy of it with one violation of each rule planted: a check that passes
// on everything would pass the first test alone.
//
//   node --test tools/test/check-layering.test.mjs
//
// Needs cargo on PATH. The copies live in a temporary directory; the
// planted `wasmtime` is an empty local crate of that name, so no plant
// downloads anything.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const tools = join(dirname(fileURLToPath(import.meta.url)), '..');
const rust = join(tools, '..', 'rust');
const check = join(tools, 'check-layering.mjs');

function run(rustDir) {
  const result = spawnSync(process.execPath, [check, '--rust-dir', rustDir], { encoding: 'utf8' });
  return { status: result.status, output: `${result.stdout}${result.stderr}` };
}

/** A copy of rust/ without build output, with `plant` applied to it. */
function planted(plant) {
  const dir = mkdtempSync(join(tmpdir(), 'aprv-layering-'));
  const copy = join(dir, 'rust');
  cpSync(rust, copy, {
    recursive: true,
    filter: (source) => !/\/(target|\.git)(\/|$)/.test(source.slice(rust.length)),
  });
  plant(copy, dir);
  return { copy, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function edit(file, from, to) {
  const text = readFileSync(file, 'utf8');
  assert.ok(text.includes(from), `${file} no longer contains ${from}`);
  writeFileSync(file, text.replace(from, to));
}

function expectFailure(name, plant, pattern) {
  test(name, () => {
    const { copy, cleanup } = planted(plant);
    try {
      const { status, output } = run(copy);
      assert.equal(status, 1, output);
      assert.match(output, pattern);
    } finally {
      cleanup();
    }
  });
}

test('the workspace as committed passes', () => {
  const { status, output } = run(rust);
  assert.equal(status, 0, output);
  assert.match(output, /check-layering: ok/);
});

expectFailure(
  'rule 1: a wasmtime dependency planted in the core fails',
  (copy, dir) => {
    const fake = join(dir, 'wasmtime');
    mkdirSync(join(fake, 'src'), { recursive: true });
    writeFileSync(join(fake, 'Cargo.toml'), '[package]\nname = "wasmtime"\nversion = "49.0.1"\nedition = "2021"\n\n[workspace]\n');
    writeFileSync(join(fake, 'src', 'lib.rs'), '');
    edit(join(copy, 'Cargo.toml'), '[dependencies]\n', `[dependencies]\nwasmtime = { path = ${JSON.stringify(fake)} }\n`);
  },
  /rule 1: the core's graph contains wasmtime/,
);

expectFailure(
  'rule 2: a serde_json dependency planted in the surface fails',
  (copy) => {
    edit(join(copy, 'bindings', 'surface', 'Cargo.toml'), '[features]', '[dependencies.serde_json]\nversion = "1"\n\n[features]');
  },
  /rule 2: aprv-surface depends on serde_json/,
);

expectFailure(
  'rule 3: the C ABI depending on the core directly fails',
  (copy) => {
    edit(
      join(copy, 'ffi', 'Cargo.toml'),
      'aprv-wire = { path = "../bindings/wire" }',
      'aprv-wire = { path = "../bindings/wire" }\napple-purchase-receipt-verifier = { path = ".." }',
    );
  },
  /rule 3: apple-purchase-receipt-verifier-ffi depends on apple-purchase-receipt-verifier directly/,
);

expectFailure(
  'rule 4: unsafe planted in the wire crate fails',
  (copy) => {
    const lib = join(copy, 'bindings', 'wire', 'src', 'lib.rs');
    writeFileSync(lib, `${readFileSync(lib, 'utf8')}\nfn planted() { let _ = unsafe { core::mem::zeroed::<u8>() }; }\n`);
  },
  /rule 4: bindings\/wire\/src\/lib\.rs \(aprv-wire\) uses unsafe/,
);

expectFailure(
  'rule 4: the surface without forbid(unsafe_code) fails',
  (copy) => {
    edit(join(copy, 'bindings', 'surface', 'src', 'lib.rs'), '#![forbid(unsafe_code)]', '');
  },
  /rule 4: aprv-surface must carry #!\[forbid\(unsafe_code\)\]/,
);

expectFailure(
  'rule 5: an asn1 module planted in the core fails',
  (copy) => {
    writeFileSync(join(copy, 'src', 'asn1.rs'), '//! A planted hand-written ASN.1 reader.\n');
    edit(join(copy, 'src', 'lib.rs'), 'mod base64;', 'mod asn1;\nmod base64;');
  },
  /rule 5: the core has a module file named asn1[\s\S]*rule 5: src\/lib\.rs declares a module named asn1/,
);

expectFailure(
  'rule 6: the header decoder named in the core fails',
  (copy) => {
    const file = join(copy, 'src', 'receipt.rs');
    writeFileSync(file, `${readFileSync(file, 'utf8')}\nfn planted() { ASN1_get_object(); }\n`);
  },
  /rule 6: src\/receipt\.rs names ASN1_get_object/,
);

expectFailure(
  'rule 6: the header decoder called in the adapter outside the walk fails',
  (copy) => {
    const file = join(copy, 'openssl', 'src', 'envelope.rs');
    writeFileSync(
      file,
      `${readFileSync(file, 'utf8')}\nfn planted() { let _ = unsafe { sys::ASN1_get_object(core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), 0) }; }\n`,
    );
  },
  /rule 6: openssl\/src\/envelope\.rs calls ASN1_get_object outside the header walk/,
);

test('rule 6: the declaration in sys.rs and the walk itself pass', () => {
  const { copy, cleanup } = planted((dir) => {
    const walk = readFileSync(join(dir, 'openssl', 'src', 'walk.rs'), 'utf8');
    assert.match(walk, /sys::ASN1_get_object\(/);
    const sys = readFileSync(join(dir, 'openssl', 'src', 'sys.rs'), 'utf8');
    assert.match(sys, /fn ASN1_get_object\(/);
  });
  try {
    const { status, output } = run(copy);
    assert.equal(status, 0, output);
  } finally {
    cleanup();
  }
});

test('unsafe inside a comment or a string is not code', () => {
  const { copy, cleanup } = planted((dir) => {
    const lib = join(dir, 'bindings', 'wire', 'src', 'lib.rs');
    writeFileSync(
      lib,
      `${readFileSync(lib, 'utf8')}\n// unsafe in a comment\n/* unsafe /* nested */ unsafe */\nconst _WORD: &str = "unsafe";\nconst _RAW: &str = r#"unsafe "quoted""#;\n`,
    );
  });
  try {
    const { status, output } = run(copy);
    assert.equal(status, 0, output);
  } finally {
    cleanup();
  }
});
