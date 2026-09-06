// Prints the vendor support status of every language line this repository
// could test, from endoflife.date, so SUPPORT-MATRIX.md can be refreshed
// against the matrices in .github/workflows/ci.yml without guessing dates.
//
// Usage: node tools/support-matrix.mjs [YYYY-MM-DD]
// The optional date replaces "today" so a snapshot can be reproduced.
//
// Swift is not tracked by endoflife.date and is left out on purpose; the
// Java dates are Oracle's (product "oracle-jdk"), which is what the
// SUPPORT-MATRIX.md tables use. Spring Boot is the one framework tracked,
// because the java-spring-boot job runs a leg per Boot line in OSS support.
const products = ['dotnet', 'nodejs', 'python', 'oracle-jdk', 'go', 'ruby', 'php', 'rust', 'spring-boot'];
const today = new Date(process.argv[2] ?? Date.now());

function status(cycle) {
  const eol = cycle.eol === false ? null : new Date(cycle.eol);
  const support = typeof cycle.support === 'string' ? new Date(cycle.support) : null;
  if (eol !== null && eol <= today) return 'EOL';
  if (support !== null && support <= today) return 'security';
  return 'active';
}

for (const product of products) {
  const response = await fetch(`https://endoflife.date/api/${product}.json`);
  if (!response.ok) {
    console.error(`${product}: HTTP ${response.status}`);
    continue;
  }
  const cycles = await response.json();
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
