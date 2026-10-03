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
// track Swift.
//
// Swift is not tracked by endoflife.date and is left out on purpose; the
// Java dates are Oracle's (product "oracle-jdk"), which is what the
// SUPPORT-MATRIX.md tables use. Spring Boot is the one framework tracked,
// because the java-spring-boot job runs a leg per Boot line in OSS support.
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

const products = ['dotnet', 'nodejs', 'python', 'oracle-jdk', 'go', 'ruby', 'php', 'rust', 'spring-boot'];
let args;
try {
  args = parseArgs({ allowPositionals: true, options: { check: { type: 'boolean' } } });
} catch (error) {
  console.error(`support-matrix: ${error.message}\nusage: node tools/support-matrix.mjs [--check] [YYYY-MM-DD]`);
  process.exit(2);
}
const { check } = args.values;
const [date] = args.positionals;
const today = new Date(date ?? Date.now());

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

function status(cycle) {
  const eol = cycle.eol === false ? null : new Date(cycle.eol);
  const support = typeof cycle.support === 'string' ? new Date(cycle.support) : null;
  if (eol !== null && eol <= today) return 'EOL';
  if (support !== null && support <= today) return 'security';
  return 'active';
}

// Every line row of SUPPORT-MATRIX.md's per-language tables: { product, line, row }.
function testedLines() {
  const path = new URL('../SUPPORT-MATRIX.md', import.meta.url);
  const rows = [];
  let product = null;
  for (const text of readFileSync(path, 'utf8').split('\n')) {
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

const all = {};
let failed = false;
for (const product of products) {
  const response = await fetch(`https://endoflife.date/api/${product}.json`);
  if (!response.ok) {
    console.error(`${product}: HTTP ${response.status}`);
    failed = true;
    continue;
  }
  const cycles = await response.json();
  all[product] = cycles;
  console.log(`\n${product}`);
  for (const cycle of cycles) {
    const state = status(cycle);
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
  const rows = testedLines();
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
    const state = status(cycle);
    console.log(`  ${product} ${line}: ${state} (eol ${cycle.eol === false ? 'open' : cycle.eol})`);
    if (state === 'EOL') {
      console.log(
        `::error::${product} ${line} is past its end of life (${cycle.eol}) and still a CI leg: ` +
          'drop it from the matrix, or mark it kept in SUPPORT-MATRIX.md with the reason',
      );
      failed = true;
    }
  }
}
process.exit(failed && check ? 1 : 0);
