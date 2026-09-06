// The root composer.json is the PHP package, and `git archive` decides what
// is in it.
//
// Packagist reads composer.json from a repository root and nowhere else, so
// this repository carries two PHP manifests: the root one Packagist and
// Composer see, and php/composer.json, which is what the port is developed
// and tested against. Two manifests drift. A `require` bumped in one and not
// the other ships a package whose declared dependencies are not the ones the
// suite ran against, and nothing in either port's own CI can notice.
//
// The archive half is the failure BOOTSTRAP.md named when it chose this
// layout: the .gitattributes allowlist silently decides what every consumer
// unpacks, and a mistake there ships a package with no php/certs/ or no
// php/src/ that installs cleanly and fails at the first call.
//
// Both halves are checked here, on every push, against the real `git archive`
// rather than against a reading of the rules.
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('..', import.meta.url));
const read = (p) => JSON.parse(readFileSync(join(repoRoot, p), 'utf8'));

const root = read('composer.json');
const dev = read('php/composer.json');
const problems = [];

// --- manifest agreement -----------------------------------------------

// Identity travels with the package, so a rename in one manifest and not the
// other publishes under a name the port does not answer to.
for (const field of ['name', 'description', 'type', 'license', 'homepage']) {
  if (JSON.stringify(root[field]) !== JSON.stringify(dev[field])) {
    problems.push(
      `composer.json ${field} is ${JSON.stringify(root[field])}, `
      + `php/composer.json says ${JSON.stringify(dev[field])}`,
    );
  }
}
if (JSON.stringify(root.keywords ?? []) !== JSON.stringify(dev.keywords ?? [])) {
  problems.push('composer.json keywords differ from php/composer.json keywords');
}

// require is the whole point: this is the constraint set a consumer resolves
// against, and php/composer.lock — the one the suite installs — is resolved
// from the other copy of it.
if (JSON.stringify(root.require ?? {}) !== JSON.stringify(dev.require ?? {})) {
  problems.push(
    'composer.json require does not match php/composer.json require:\n'
    + `    root: ${JSON.stringify(root.require ?? {})}\n`
    + `    php/: ${JSON.stringify(dev.require ?? {})}`,
  );
}

// The root manifest is deliberately not the development one: require-dev
// belongs to php/composer.json, where php/composer.lock can pin it.
if (root['require-dev'] !== undefined) {
  problems.push('composer.json declares require-dev; the development manifest is php/composer.json');
}

// Same namespaces, each rebased onto php/ because the root manifest's paths
// are resolved from the repository root.
const rootPsr4 = root.autoload?.['psr-4'] ?? {};
const devPsr4 = dev.autoload?.['psr-4'] ?? {};
for (const [ns, dir] of Object.entries(devPsr4)) {
  const expected = `php/${dir}`;
  if (rootPsr4[ns] !== expected) {
    problems.push(
      `composer.json autoload psr-4 maps ${ns} to ${JSON.stringify(rootPsr4[ns])}, expected ${JSON.stringify(expected)}`,
    );
  }
}
for (const ns of Object.keys(rootPsr4)) {
  if (!(ns in devPsr4)) {
    problems.push(`composer.json autoload psr-4 declares ${ns}, which php/composer.json does not`);
  }
}

// --- the archive ------------------------------------------------------

// `git archive HEAD` is what GitHub serves as the zipball and what Composer
// unpacks. Reading it is the only way to test the .gitattributes rules; a
// dry reading of the rules is what the allowlist exists to avoid trusting.
const listing = execFileSync('git', ['archive', 'HEAD'], { cwd: repoRoot, maxBuffer: 256 * 1024 * 1024 });
const entries = execFileSync('tar', ['-t'], { input: listing, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
  .split('\n')
  .filter((line) => line !== '' && !line.endsWith('/'));

const roots = readdirSync(join(repoRoot, 'certs')).filter((n) => n.endsWith('.cer')).sort();
const required = [
  'composer.json',
  'LICENSE',
  'php/composer.json',
  'php/LICENSE',
  'php/README.md',
  'php/src/AppleRootCerts.php',
  'php/src/Jws/JwsVerifier.php',
  'php/src/Receipt/ReceiptVerifier.php',
  'php/src/Internal/RootsData.php',
  ...roots.map((n) => `php/certs/${n}`),
];
for (const path of required) {
  if (!entries.includes(path)) problems.push(`git archive is missing ${path}`);
}

// Every php/src file, not just the four named above: a psr-4 root that
// half-ships is a fatal on whichever class the consumer happens to touch.
const srcFiles = [];
(function walk(dir) {
  for (const entry of readdirSync(join(repoRoot, dir), { withFileTypes: true })) {
    if (entry.isDirectory()) walk(`${dir}/${entry.name}`);
    else if (entry.name.endsWith('.php')) srcFiles.push(`${dir}/${entry.name}`);
  }
}('php/src'));
for (const path of srcFiles) {
  if (!entries.includes(path)) problems.push(`git archive is missing ${path}`);
}

// The other direction. Anything not on the allowlist is either another
// port riding along inside the PHP package or development weight
// (php/tests, php/fuzz, php/tools, the tool configs, php/composer.lock).
const allowed = (path) =>
  path === 'composer.json'
  || path === 'LICENSE'
  || path === 'php/composer.json'
  || path === 'php/LICENSE'
  || path === 'php/README.md'
  || path.startsWith('php/src/')
  || path.startsWith('php/certs/');
const ports = new Set(['dotnet', 'go', 'java', 'jvm-interop', 'node', 'python', 'ruby', 'rust', 'swift']);
for (const path of entries) {
  if (allowed(path)) continue;
  const top = path.split('/')[0];
  problems.push(
    ports.has(top)
      ? `git archive carries ${path}: the ${top} port is inside the PHP package`
      : `git archive carries ${path}, which is not on the .gitattributes allowlist`,
  );
}

if (problems.length > 0) {
  for (const problem of problems) console.error(`check-php-package: ${problem}`);
  process.exit(1);
}
console.log(`check-php-package: OK — manifests agree, archive carries ${entries.length} files.`);
for (const path of entries.filter((p) => !p.startsWith('php/src/')).sort()) console.log(`  ${path}`);
console.log(`  php/src/ (${srcFiles.length} files)`);
