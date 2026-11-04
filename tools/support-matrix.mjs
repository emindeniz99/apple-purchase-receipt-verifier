// Prints the vendor support status of every language line this repository
// could test, from endoflife.date, so SUPPORT-MATRIX.md can be refreshed
// against the matrices in .github/workflows/ci.yml without guessing dates.
//
// Usage: node tools/support-matrix.mjs [--check] [YYYY-MM-DD]
// The optional date replaces "today" so a snapshot can be reproduced.
//
// --check also reads the line tables of SUPPORT-MATRIX.md, which list every
// line CI tests, and exits 1 when one of them is past its vendor's end of
// life, so the scheduled support-matrix workflow tells the owner. A row
// that says "floor" or "kept" stays past EOL on purpose (the rule in
// SUPPORT-MATRIX.md) and is not checked; neither is a line endoflife.date
// does not list, which is reported instead. Rust and Swift have no table
// row to check: CI tests Rust's current stable, and endoflife.date does not
// track Swift (api/swift.json answered 404 on 2026-11-04).
//
// --check also warns, without failing, when the vendor supports a line
// newer than the newest one CI tests (SUPPORT-MATRIX.md rule 3: a new
// major joins the matrix in the first pull request after its GA). Elixir
// and Erlang/OTP have no SUPPORT-MATRIX.md table, because elixir-ffi is an
// example rather than a port; their tested lines come from that job's
// matrix in ci.yml, and only this warning applies to them, since the
// job's first leg is the floor mix.exs claims.
//
// The Java dates are Oracle's (product "oracle-jdk"), which is what the
// SUPPORT-MATRIX.md tables use. Spring Boot is the one framework tracked,
// because the java-spring-boot job runs a leg per Boot line in OSS support.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

const products = ['dotnet', 'nodejs', 'python', 'oracle-jdk', 'go', 'ruby', 'php', 'rust', 'spring-boot', 'elixir', 'erlang'];

// SUPPORT-MATRIX.md's headings, mapped to endoflife.date's product names.
const sections = {
  '.NET': 'dotnet',
  Node: 'nodejs',
  Python: 'python',
  Java: 'oracle-jdk',
  'Spring Boot (consumer smoke)': 'spring-boot',
  Go: 'go',
  Ruby: 'ruby',
  PHP: 'php',
};

export function status(cycle, today) {
  const eol = cycle.eol === false ? null : new Date(cycle.eol);
  const support = typeof cycle.support === 'string' ? new Date(cycle.support) : null;
  if (eol !== null && eol <= today) return 'EOL';
  if (support !== null && support <= today) return 'security';
  return 'active';
}

// Every line row of SUPPORT-MATRIX.md's per-language tables: { product, line, row }.
export function testedLines(markdown) {
  const rows = [];
  let product = null;
  for (const text of markdown.split('\n')) {
    const heading = /^(#{2,4}) (.*)$/.exec(text);
    if (heading) {
      product = heading[1] === '##' ? null : (sections[heading[2].trim()] ?? null);
      continue;
    }
    if (!product || !text.startsWith('|')) continue;
    const line = text.split('|')[1].trim();
    if (line === 'Line' || /^-+$/.test(line)) continue;
    rows.push({ product, line, row: text });
  }
  return rows;
}

// The Erlang/OTP and Elixir lines of ci.yml's elixir-ffi matrix, as
// { product, line }.
export function elixirLines(workflow) {
  const job = /^ {2}elixir-ffi:\n([\s\S]*?)(?=^ {2}\S|(?![\s\S]))/m.exec(workflow);
  if (!job) throw new Error('ci.yml has no elixir-ffi job');
  // A commented-out leg is not a tested line.
  const body = job[1].replace(/^\s*#.*$/gm, '');
  const lines = [
    ...[...body.matchAll(/\botp: "([^"]+)"/g)].map((m) => ({ product: 'erlang', line: m[1] })),
    ...[...body.matchAll(/\belixir: "([^"]+)"/g)].map((m) => ({ product: 'elixir', line: m[1] })),
  ];
  for (const product of ['erlang', 'elixir']) {
    if (!lines.some((l) => l.product === product)) throw new Error(`ci.yml's elixir-ffi matrix names no ${product} line`);
  }
  return lines;
}

// Numeric, part by part; "8.0" and "8" are the same line.
function compare(a, b) {
  const x = String(a).split('.').map(Number);
  const y = String(b).split('.').map(Number);
  for (let i = 0; i < Math.max(x.length, y.length); i += 1) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

const numeric = (line) => /^\d+(\.\d+)*$/.test(String(line));

// For each product with tested lines, the newest released cycle that is not
// past its end of life when it is newer than every tested line:
// [{ product, cycle, newest }], `newest` being the newest tested line.
export function untestedNewer(cycles, tested, today) {
  const found = [];
  for (const product of [...new Set(tested.map((t) => t.product))]) {
    if (!cycles[product]) continue;
    const lines = tested.filter((t) => t.product === product && numeric(t.line)).map((t) => t.line);
    if (lines.length === 0) continue;
    const newest = lines.reduce((a, b) => (compare(b, a) > 0 ? b : a));
    const ahead = cycles[product].filter(
      (c) =>
        numeric(c.cycle) &&
        compare(c.cycle, newest) > 0 &&
        typeof c.releaseDate === 'string' &&
        new Date(c.releaseDate) <= today &&
        status(c, today) !== 'EOL',
    );
    if (ahead.length === 0) continue;
    found.push({ product, cycle: ahead.reduce((a, b) => (compare(b.cycle, a.cycle) > 0 ? b : a)), newest });
  }
  return found;
}

async function main() {
  let args;
  try {
    args = parseArgs({ allowPositionals: true, options: { check: { type: 'boolean' } } });
  } catch (error) {
    console.error(`support-matrix: ${error.message}\nusage: node tools/support-matrix.mjs [--check] [YYYY-MM-DD]`);
    return 2;
  }
  const { check } = args.values;
  const [date] = args.positionals;
  const today = new Date(date ?? Date.now());

  const all = {};
  let failed = false;
  for (const product of products) {
    const response = await fetch(`https://endoflife.date/api/${product}.json`);
    if (!response.ok) {
      // Elixir and Erlang/OTP only feed the newer-line warning, so their
      // outage is a warning too; every other product can fail --check.
      if (product === 'elixir' || product === 'erlang') {
        console.log(`::warning::${product}: endoflife.date answered HTTP ${response.status}; its newer-line check is skipped`);
      } else {
        console.error(`${product}: HTTP ${response.status}`);
        failed = true;
      }
      continue;
    }
    const cycles = await response.json();
    all[product] = cycles;
    console.log(`\n${product}`);
    for (const cycle of cycles) {
      const state = status(cycle, today);
      if (state === 'EOL' && product === 'rust') continue;
      const lts = cycle.lts === true || typeof cycle.lts === 'string' ? 'LTS' : '';
      const ends = cycle.eol === false ? 'open' : cycle.eol;
      console.log(
        `  ${String(cycle.cycle).padEnd(8)} ${lts.padEnd(3)} ${state.padEnd(8)} ` +
          `latest ${String(cycle.latest).padEnd(10)} support ${String(cycle.support ?? '-').padEnd(10)} eol ${ends}`,
      );
    }
  }

  if (check) {
    console.log(`\nSUPPORT-MATRIX.md's tested lines on ${today.toISOString().slice(0, 10)}`);
    const rows = testedLines(readFileSync(new URL('../SUPPORT-MATRIX.md', import.meta.url), 'utf8'));
    if (rows.length === 0) {
      console.log('::error::no line rows found in SUPPORT-MATRIX.md; the table layout changed');
      failed = true;
    }
    for (const { product, line, row } of rows) {
      if (/\b(floor|kept)\b/.test(row)) {
        console.log(`  ${product} ${line}: a floor or kept line, which stays a leg past EOL; not checked`);
        continue;
      }
      if (!all[product]) continue;
      const cycle = all[product].find((c) => String(c.cycle) === line || String(c.cycle) === line.replace(/\.0$/, ''));
      if (!cycle) {
        console.log(`  ${product} ${line}: endoflife.date lists no such cycle, not checked`);
        continue;
      }
      const state = status(cycle, today);
      console.log(`  ${product} ${line}: ${state} (eol ${cycle.eol === false ? 'open' : cycle.eol})`);
      if (state === 'EOL') {
        console.log(
          `::error::${product} ${line} is past its end of life (${cycle.eol}) and still a CI leg: ` +
            'drop it from the matrix, or mark it kept in SUPPORT-MATRIX.md with the reason',
        );
        failed = true;
      }
    }

    console.log('\nSupported lines newer than the newest one CI tests');
    const elixir = elixirLines(readFileSync(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8'));
    const newer = untestedNewer(all, [...rows, ...elixir], today);
    if (newer.length === 0) console.log('  none');
    for (const { product, cycle, newest } of newer) {
      const where = product === 'elixir' || product === 'erlang' ? "elixir-ffi's matrix in ci.yml" : 'the matrix and SUPPORT-MATRIX.md';
      console.log(
        `::warning::${product} ${cycle.cycle} (released ${cycle.releaseDate}) is supported and newer than ` +
          `${newest}, the newest line CI tests: add it to ${where}`,
      );
    }
  }
  return failed && check ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(await main());
}
