import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { elixirLines, status, testedLines, untestedNewer } from '../support-matrix.mjs';

const root = new URL('../../', import.meta.url);
const read = (file) => readFileSync(new URL(file, root), 'utf8');
const today = new Date('2026-11-04');

test('a cycle is EOL, security-only or active on the given day', () => {
  assert.equal(status({ eol: '2026-10-31', support: '2025-10-01' }, today), 'EOL');
  assert.equal(status({ eol: '2028-10-31', support: '2026-10-01' }, today), 'security');
  assert.equal(status({ eol: false, support: true }, today), 'active');
});

test('reads the line rows of SUPPORT-MATRIX.md under the headings it knows', () => {
  const markdown = [
    '## Snapshot',
    '### Python',
    '| Line | Status | Ends | CI |',
    '|---|---|---|---|',
    '| 3.11 | floor, security | 2027-10-31 | `python` |',
    '| 3.14 | active | 2030-10-31 | `python` |',
    '### Rust',
    '| Line | Status | CI |',
    '| stable | active | `rust` |',
    '## Platforms per package',
    '| Package | Runs on | Tested |',
  ].join('\n');
  assert.deepEqual(
    testedLines(markdown).map(({ product, line }) => ({ product, line })),
    [{ product: 'python', line: '3.11' }, { product: 'python', line: '3.14' }],
  );
  const real = testedLines(read('SUPPORT-MATRIX.md'));
  for (const product of ['dotnet', 'nodejs', 'python', 'oracle-jdk', 'spring-boot', 'go', 'ruby', 'php']) {
    assert.ok(real.some((r) => r.product === product), `SUPPORT-MATRIX.md has no ${product} row`);
  }
});

test('reads the OTP and Elixir lines from the elixir-ffi job only', () => {
  const workflow = [
    'jobs:',
    '  elixir-ffi:',
    '    strategy:',
    '      matrix:',
    '        include:',
    '          - otp: "27"',
    '            elixir: "1.18"',
    '          - otp: "28"',
    '            elixir: "1.20"',
    '          # - otp: "29"',
    '          #   elixir: "1.21"',
    '  other:',
    '    with:',
    '      otp: "99"',
  ].join('\n');
  assert.deepEqual(elixirLines(workflow), [
    { product: 'erlang', line: '27' },
    { product: 'erlang', line: '28' },
    { product: 'elixir', line: '1.18' },
    { product: 'elixir', line: '1.20' },
  ]);
  // A renamed job or matrix must fail the check, not drop the warning.
  assert.throws(() => elixirLines('jobs:\n  beam:\n'), /no elixir-ffi job/);
  assert.throws(() => elixirLines('jobs:\n  elixir-ffi:\n    runs-on: x\n'), /names no erlang line/);
  const real = elixirLines(read('.github/workflows/ci.yml'));
  assert.ok(real.some((l) => l.product === 'erlang') && real.some((l) => l.product === 'elixir'));
});

test('warns about a supported line newer than the newest one tested', () => {
  const cycles = {
    python: [
      { cycle: '3.16', releaseDate: '2027-10-01', eol: '2032-10-31' },
      { cycle: '3.15', releaseDate: '2026-10-09', eol: '2031-10-31' },
      { cycle: '3.14', releaseDate: '2025-10-07', eol: '2030-10-31' },
    ],
    dotnet: [
      { cycle: '10', releaseDate: '2025-11-11', eol: '2028-11-14' },
      { cycle: '8', releaseDate: '2023-11-14', eol: '2026-11-10' },
    ],
    'oracle-jdk': [
      { cycle: '26', releaseDate: '2026-03-17', eol: '2026-09-18' },
      { cycle: '25', releaseDate: '2025-09-16', eol: '2030-09-30' },
    ],
    erlang: [{ cycle: '29', releaseDate: '2026-05-11', support: true, eol: '2029-05-11' }],
  };
  const tested = [
    { product: 'python', line: '3.11' },
    { product: 'python', line: '3.14' },
    // "10.0" is cycle "10"; a non-numeric row is not a line to compare.
    { product: 'dotnet', line: '10.0' },
    { product: 'dotnet', line: 'netstandard2.0' },
    // A newer cycle already past its end of life is no line to add.
    { product: 'oracle-jdk', line: '25' },
    { product: 'erlang', line: '27' },
    { product: 'erlang', line: '28' },
    // endoflife.date tracks nothing for it: no warning, no error.
    { product: 'swift', line: '6.4' },
  ];
  const found = untestedNewer(cycles, tested, today).map(({ product, cycle, newest }) => [product, cycle.cycle, newest]);
  // 3.16 is not released yet on this day.
  assert.deepEqual(found, [['python', '3.15', '3.14'], ['erlang', '29', '28']]);
  assert.deepEqual(untestedNewer(cycles, [{ product: 'python', line: '3.15' }], today), []);
});
