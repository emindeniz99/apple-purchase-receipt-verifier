// Tests for .github/scripts/fuzz-finding.sh, the nightly job's handling of
// a fuzz finding (docs/rust-core/DECISIONS.md R37). The repository is
// public, so what matters is what the script lets out: the public log must
// carry the target and the input's SHA-256 and nothing of the input, the
// stack or the panic message; the sealed file must open with the owner's
// key and hold the reproducer and the fuzzer's report; with no key nothing
// is sealed; and the Telegram notice carries only the four fields.
//
// age and age-keygen come from AGE_DIR (.github/scripts/install-age.sh
// puts the pinned release there) or from PATH. Each test makes its own
// throwaway key.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('../../.github/scripts/fuzz-finding.sh', import.meta.url));
const tool = (name) => (process.env.AGE_DIR ? join(process.env.AGE_DIR, name) : name);
const AGE = tool('age');
const AGE_KEYGEN = tool('age-keygen');

// Bytes that must never reach the log: a marker in the input, and the kind
// of text libFuzzer and a Rust panic print about it.
const INPUT = Buffer.from('MIIB-SECRET-INPUT-MARKER\x00\x01\x02');
const REPORT = [
  '==1234==ERROR: AddressSanitizer: heap-buffer-overflow',
  "thread '<unnamed>' panicked at src/receipt.rs:42:7: PANIC-MESSAGE-MARKER",
  '    #0 0x55 in apple_purchase_receipt_verifier::receipt::parse STACK-MARKER',
  'Base64: TUlJQi1TRUNSRVQtSU5QVVQtTUFSS0VS',
].join('\n');
const LEAKS = ['SECRET-INPUT-MARKER', 'PANIC-MESSAGE-MARKER', 'STACK-MARKER', 'TUlJQi1TRUNSRVQt', 'AddressSanitizer', '::'];
const SHA = createHash('sha256').update(INPUT).digest('hex');

/** A finding as libFuzzer leaves it: the reproducer, a slow unit beside it
 * (not a finding) and the target's whole log. */
function finding({ withInput = true } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'fuzz-finding-'));
  const artifacts = join(dir, 'artifacts');
  mkdirSync(artifacts);
  if (withInput) writeFileSync(join(artifacts, 'crash-0123abcd'), INPUT);
  writeFileSync(join(artifacts, 'slow-unit-4567'), 'SLOW-UNIT-MARKER');
  writeFileSync(join(dir, 'fuzzer.log'), REPORT);
  return { dir, artifacts, log: join(dir, 'fuzzer.log'), sealed: join(dir, 'sealed'), summary: join(dir, 'summary.md') };
}

/** A throwaway age identity and a recipients file holding its public line,
 * as the owner will commit it. */
function key(dir) {
  const identity = join(dir, 'identity.txt');
  const r = spawnSync(AGE_KEYGEN, ['-o', identity], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const pub = /^# public key: (age1\S+)$/m.exec(readFileSync(identity, 'utf8'))[1];
  const recipient = join(dir, 'findings-recipient.txt');
  writeFileSync(recipient, `${pub}\n`);
  return { identity, recipient };
}

/** Runs the script without blocking the event loop, so a local Bot API
 * stand-in in this process can answer it. */
function run(f, env) {
  writeFileSync(f.summary, '');
  return new Promise((resolve) => {
    const child = spawn('bash', [script, 'verify-receipt', f.artifacts, f.log, f.sealed], {
      env: {
        PATH: process.env.PATH,
        AGE,
        GITHUB_STEP_SUMMARY: f.summary,
        GITHUB_REPOSITORY: 'owner/repo',
        RUN_URL: 'https://github.com/owner/repo/actions/runs/1',
        ...env,
      },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

function assertNoLeak(r, f) {
  for (const leak of LEAKS) {
    assert.ok(!r.stdout.includes(leak), `stdout carries ${leak}:\n${r.stdout}`);
    assert.ok(!r.stderr.includes(leak), `stderr carries ${leak}:\n${r.stderr}`);
  }
  assert.equal(readFileSync(f.summary, 'utf8'), '', 'the step summary was written');
}

test('with a recipient key: the log has the hash only, and the sealed file opens with the key', async () => {
  const f = finding();
  const k = key(f.dir);
  const r = await run(f, { FINDINGS_RECIPIENT: k.recipient });
  assert.equal(r.status, 0, r.stderr);
  assertNoLeak(r, f);
  assert.deepEqual(r.stdout.trim().split('\n'), [
    `fuzz: verify-receipt found a crash; input sha256 ${SHA}`,
    'fuzz: verify-receipt sealed to the recipient key',
    'telegram notice skipped: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is not set',
  ]);
  assert.deepEqual(readdirSync(f.sealed), ['verify-receipt.tar.age']);

  const out = join(f.dir, 'opened');
  mkdirSync(out);
  const tarFile = join(f.dir, 'opened.tar');
  const dec = spawnSync(AGE, ['-d', '-i', k.identity, '-o', tarFile, join(f.sealed, 'verify-receipt.tar.age')], { encoding: 'utf8' });
  assert.equal(dec.status, 0, dec.stderr);
  assert.equal(spawnSync('tar', ['-xf', tarFile, '-C', out]).status, 0);
  assert.deepEqual(readdirSync(join(out, 'verify-receipt')).sort(), ['crash-0123abcd', 'fuzzer.log']);
  assert.deepEqual(readFileSync(join(out, 'verify-receipt', 'crash-0123abcd')), INPUT);
  assert.equal(readFileSync(join(out, 'verify-receipt', 'fuzzer.log'), 'utf8'), REPORT);

  // Without the identity the sealed file is noise to anyone downloading it.
  const sealed = readFileSync(join(f.sealed, 'verify-receipt.tar.age'));
  assert.ok(!sealed.includes('SECRET-INPUT-MARKER') && !sealed.includes('PANIC-MESSAGE-MARKER'));
});

test('without a recipient key: nothing is sealed, one withheld line carries the hash', async () => {
  const f = finding();
  const r = await run(f, { FINDINGS_RECIPIENT: join(f.dir, 'absent.txt') });
  assert.equal(r.status, 0, r.stderr);
  assertNoLeak(r, f);
  assert.deepEqual(r.stdout.trim().split('\n'), [
    `fuzz: verify-receipt found a crash; input sha256 ${SHA}`,
    `finding withheld: no recipient key; target verify-receipt, input sha256 ${SHA}`,
    'telegram notice skipped: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is not set',
  ]);
  assert.equal(existsSync(f.sealed), false);
});

test('a recipients file of comments only counts as no key', async () => {
  const f = finding();
  const recipient = join(f.dir, 'comments.txt');
  writeFileSync(recipient, '# the owner adds the public line here\n\n');
  const r = await run(f, { FINDINGS_RECIPIENT: recipient });
  assert.match(r.stdout, /^finding withheld: no recipient key; /m);
  assert.equal(existsSync(f.sealed), false);
});

test('a recipients file age refuses: nothing is sealed, nothing leaks', async () => {
  const f = finding();
  const recipient = join(f.dir, 'bad.txt');
  writeFileSync(recipient, 'not-an-age-key\n');
  const r = await run(f, { FINDINGS_RECIPIENT: recipient });
  assert.equal(r.status, 0, r.stderr);
  assertNoLeak(r, f);
  assert.match(r.stdout, new RegExp(`^finding withheld: the recipient key was refused; target verify-receipt, input sha256 ${SHA}$`, 'm'));
  assert.deepEqual(existsSync(f.sealed) ? readdirSync(f.sealed) : [], []);
});

test('a failure without a reproducer: hash "none", and the log is still sealed', async () => {
  const f = finding({ withInput: false });
  const k = key(f.dir);
  const r = await run(f, { FINDINGS_RECIPIENT: k.recipient });
  assertNoLeak(r, f);
  assert.match(r.stdout, /^fuzz: verify-receipt failed without a crashing input; its log stays sealed$/m);
  assert.deepEqual(readdirSync(f.sealed), ['verify-receipt.tar.age']);
});

test('the Telegram notice carries the repository, target, hash and run URL, and the log never shows the token', async () => {
  const f = finding();
  const requests = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (d) => (body += d));
    req.on('end', () => {
      requests.push({ method: req.method, url: req.url, body: new URLSearchParams(body) });
      res.setHeader('content-type', 'application/json');
      res.end('{"ok":true}');
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const token = '123456:AAbb-cc_DD';
  try {
    const r = await run(f, {
      FINDINGS_RECIPIENT: join(f.dir, 'absent.txt'),
      TELEGRAM_BOT_TOKEN: token,
      TELEGRAM_CHAT_ID: '-1001234',
      TELEGRAM_API: `http://127.0.0.1:${server.address().port}`,
    });
    assert.equal(r.status, 0, r.stderr);
    assertNoLeak(r, f);
    assert.ok(!r.stdout.includes(token) && !r.stderr.includes(token));
    assert.match(r.stdout, /^telegram notice sent$/m);
  } finally {
    server.close();
  }
  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, 'POST');
  assert.equal(requests[0].url, `/bot${token}/sendMessage`);
  assert.deepEqual([...requests[0].body.keys()].sort(), ['chat_id', 'text']);
  assert.equal(requests[0].body.get('chat_id'), '-1001234');
  assert.equal(
    requests[0].body.get('text'),
    `repository: owner/repo\ntarget: verify-receipt\ninput sha256: ${SHA}\nrun: https://github.com/owner/repo/actions/runs/1`,
  );
});

test('a Bot API that fails: one line, and the script still ends normally', async () => {
  const f = finding();
  const r = await run(f, {
    FINDINGS_RECIPIENT: join(f.dir, 'absent.txt'),
    TELEGRAM_BOT_TOKEN: '1:x',
    TELEGRAM_CHAT_ID: '1',
    TELEGRAM_API: 'http://127.0.0.1:9',
  });
  assert.equal(r.status, 0, r.stderr);
  assertNoLeak(r, f);
  assert.match(r.stdout, /^telegram notice failed$/m);
});
