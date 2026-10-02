// Tests for .github/scripts/fuzz-quiet.sh and fuzz-report.sh, the two
// steps every fuzz job runs around its targets (docs/rust-core/DECISIONS.md
// R37). fuzz-finding.sh has its own test; this one proves the steps around
// it: the quiet step keeps a target's output off its own stdout and stderr
// and lists what failed; the report step hands each listed target to
// fuzz-finding.sh, so the job log carries hashes only, the sealed files
// open to the input and the log, and the step exits 1.
//
// The harness is a fake run.sh whose `list` names the targets the quiet
// step runs (TARGETS in its environment): one that passes, one that writes
// a crashing input and prints a report, one that fails without writing
// anything. age comes from AGE_DIR or PATH, as in fuzz-finding.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const scripts = fileURLToPath(new URL('../../.github/scripts/', import.meta.url));
const tool = (name) => (process.env.AGE_DIR ? join(process.env.AGE_DIR, name) : name);
const AGE = tool('age');
const AGE_KEYGEN = tool('age-keygen');

const INPUT = Buffer.from('MIIB-SECRET-INPUT-MARKER\x00\x01\x02');
const REPORT = [
  '==1234==ERROR: AddressSanitizer: heap-buffer-overflow',
  "thread '<unnamed>' panicked at src/receipt.rs:42:7: PANIC-MESSAGE-MARKER",
  '    #0 0x55 in apple_purchase_receipt_verifier::receipt::parse STACK-MARKER',
  'Base64: TUlJQi1TRUNSRVQtSU5QVVQtTUFSS0VS',
].join('\n');
const LEAKS = ['SECRET-INPUT-MARKER', 'PANIC-MESSAGE-MARKER', 'STACK-MARKER', 'TUlJQi1TRUNSRVQt', 'AddressSanitizer', '::'];
const SHA = createHash('sha256').update(INPUT).digest('hex');

/** A harness directory with a fake run.sh and a fresh RUNNER_TEMP. */
function harness() {
  const dir = mkdtempSync(join(tmpdir(), 'fuzz-steps-'));
  const cwd = join(dir, 'harness');
  const temp = join(dir, 'runner-temp');
  mkdirSync(cwd);
  mkdirSync(temp);
  // `good` fuzzes for its budget; `bad` leaves a crashing input and
  // reports it the way libFuzzer and a Rust panic do; `silent` fails with
  // nothing written. Every line of output is a leak if it reaches the
  // step's stdout or stderr.
  writeFileSync(
    join(cwd, 'run.sh'),
    `#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  list) [ "$TARGETS" = fail ] && exit 3; for t in $TARGETS; do echo "$t"; done ;;
  good) echo "fuzzing for $2 s: PANIC-MESSAGE-MARKER would not be here but STACK-MARKER could"; exit 0 ;;
  bad)
    mkdir -p artifacts/bad
    printf '%s' "$INPUT_B64" | base64 -d > artifacts/bad/crash-0123abcd
    printf '%s\\n' "$REPORT" ; printf '%s\\n' "$REPORT" >&2
    exit 1 ;;
  silent) echo "STACK-MARKER" >&2; exit 77 ;;
esac
`,
  );
  chmodSync(join(cwd, 'run.sh'), 0o755);
  const summary = join(dir, 'summary.md');
  writeFileSync(summary, '');
  return { dir, cwd, temp, summary, list: join(temp, 'fuzz-failed.tsv'), logs: join(temp, 'fuzz-logs'), sealed: join(temp, 'fuzz-sealed') };
}

function key(dir) {
  const identity = join(dir, 'identity.txt');
  const r = spawnSync(AGE_KEYGEN, ['-o', identity], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const pub = /^# public key: (age1\S+)$/m.exec(readFileSync(identity, 'utf8'))[1];
  const recipient = join(dir, 'findings-recipient.txt');
  writeFileSync(recipient, `${pub}\n`);
  return { identity, recipient };
}

function quiet(h, targets) {
  return spawnSync('bash', [join(scripts, 'fuzz-quiet.sh'), 'artifacts', '7'], {
    cwd: h.cwd,
    encoding: 'utf8',
    env: {
      PATH: process.env.PATH,
      RUNNER_TEMP: h.temp,
      TARGETS: targets.join(' '),
      INPUT_B64: INPUT.toString('base64'),
      REPORT,
      GITHUB_STEP_SUMMARY: h.summary,
    },
  });
}

function report(h, env) {
  return spawnSync('bash', [join(scripts, 'fuzz-report.sh')], {
    cwd: h.dir,
    encoding: 'utf8',
    env: {
      PATH: process.env.PATH,
      RUNNER_TEMP: h.temp,
      AGE,
      GITHUB_STEP_SUMMARY: h.summary,
      GITHUB_REPOSITORY: 'owner/repo',
      RUN_URL: 'https://github.com/owner/repo/actions/runs/1',
      ...env,
    },
  });
}

function assertNoLeak(r, h) {
  for (const leak of LEAKS) {
    assert.ok(!r.stdout.includes(leak), `stdout carries ${leak}:\n${r.stdout}`);
    assert.ok(!r.stderr.includes(leak), `stderr carries ${leak}:\n${r.stderr}`);
  }
  assert.equal(readFileSync(h.summary, 'utf8'), '', 'the step summary was written');
}

test('the quiet step: one line per target, the output in files, the failed targets listed', () => {
  const h = harness();
  writeFileSync(h.list, 'stale\tfrom\tbefore\n'); // must be truncated, not appended to
  const r = quiet(h, ['good', 'bad', 'silent']);
  assert.equal(r.status, 1);
  assertNoLeak(r, h);
  assert.deepEqual(r.stdout.trim().split('\n'), [
    'fuzz: good ran 7 s without a finding',
    'fuzz: bad failed; its output stays on the runner',
    'fuzz: silent failed; its output stays on the runner',
  ]);
  assert.equal(r.stderr, '');
  assert.deepEqual(readFileSync(h.list, 'utf8'), [
    `bad\t${h.cwd}/artifacts/bad\t${h.logs}/bad.log\n`,
    `silent\t${h.cwd}/artifacts/silent\t${h.logs}/silent.log\n`,
  ].join(''));
  // The output went to the files, both streams of it.
  assert.equal(readFileSync(join(h.logs, 'bad.log'), 'utf8'), `${REPORT}\n${REPORT}\n`);
  assert.equal(readFileSync(join(h.logs, 'silent.log'), 'utf8'), 'STACK-MARKER\n');
  assert.match(readFileSync(join(h.logs, 'good.log'), 'utf8'), /^fuzzing for 7 s/);
});

test('the quiet step with every target clean: exit 0 and an empty list', () => {
  const h = harness();
  writeFileSync(h.list, 'stale\tfrom\tbefore\n');
  const r = quiet(h, ['good']);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(readFileSync(h.list, 'utf8'), '');
});

test('the quiet step refuses a harness whose list fails or names nothing: no target would run', () => {
  for (const targets of [[], ['fail']]) {
    const h = harness();
    const r = quiet(h, targets);
    assert.equal(r.status, 2, `${targets}: ${r.stdout}${r.stderr}`);
    assert.equal(r.stdout, '');
    assert.equal(r.stderr, 'fuzz: ./run.sh list named no target\n');
    assert.equal(readFileSync(h.list, 'utf8'), '');
  }
});

test('the report step: hashes only in the log, the sealed files open to input and log, exit 1', () => {
  const h = harness();
  assert.equal(quiet(h, ['good', 'bad', 'silent']).status, 1);
  const k = key(h.dir);
  const r = report(h, { FINDINGS_RECIPIENT: k.recipient });
  assert.equal(r.status, 1);
  assertNoLeak(r, h);
  assert.deepEqual(r.stdout.trim().split('\n'), [
    `fuzz: bad found a crash; input sha256 ${SHA}`,
    'fuzz: bad sealed to the recipient key',
    'telegram notice skipped: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is not set',
    'fuzz: silent failed without a crashing input; its log stays sealed',
    'fuzz: silent sealed to the recipient key',
    'telegram notice skipped: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is not set',
  ]);
  assert.deepEqual(readdirSync(h.sealed).sort(), ['bad.tar.age', 'silent.tar.age']);

  const opened = join(h.dir, 'opened');
  mkdirSync(opened);
  for (const t of ['bad', 'silent']) {
    const tarFile = join(h.dir, `${t}.tar`);
    const dec = spawnSync(AGE, ['-d', '-i', k.identity, '-o', tarFile, join(h.sealed, `${t}.tar.age`)], { encoding: 'utf8' });
    assert.equal(dec.status, 0, dec.stderr);
    assert.equal(spawnSync('tar', ['-xf', tarFile, '-C', opened]).status, 0);
  }
  assert.deepEqual(readdirSync(join(opened, 'bad')).sort(), ['crash-0123abcd', 'fuzzer.log']);
  assert.deepEqual(readFileSync(join(opened, 'bad', 'crash-0123abcd')), INPUT);
  assert.equal(readFileSync(join(opened, 'bad', 'fuzzer.log'), 'utf8'), `${REPORT}\n${REPORT}\n`);
  assert.deepEqual(readdirSync(join(opened, 'silent')), ['fuzzer.log']);
  assert.equal(readFileSync(join(opened, 'silent', 'fuzzer.log'), 'utf8'), 'STACK-MARKER\n');
});

test('the report step with an empty list: an earlier step failed, and it says so', () => {
  const h = harness();
  writeFileSync(h.list, '');
  const r = report(h, {});
  assert.equal(r.status, 1);
  assert.equal(r.stdout.trim(), 'fuzz: no target finding to report; an earlier step failed');
  assert.equal(existsSync(h.sealed), false);
});
