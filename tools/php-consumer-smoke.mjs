// Install the PHP package the way a stranger would, and verify a receipt
// with it.
//
// Everything upstream of this — phpunit, phpstan, the drift guard — reads
// php/src/ from a checkout. A Composer consumer never sees a checkout. It
// sees whatever the .gitattributes allowlist let into GitHub's zipball,
// unpacked under vendor/, autoloaded by the ROOT composer.json's psr-4 root.
// This builds exactly that and runs a verification through it.
//
// The package comes from an extracted `git archive HEAD` behind a `path`
// repository rather than from a `vcs` repository pointing at the clone,
// because the archive is the artifact under test: a vcs repository would
// hand Composer a working tree and prove nothing about the export-ignore
// rules. `symlink: false` makes Composer copy rather than link, so the
// autoload paths under vendor/ are the real ones.
//
// --no-scripts for the same reason every composer install in ci.yml carries
// it. psr/clock still comes from packagist.org; there is nothing else in the
// resolved graph.
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('..', import.meta.url));
const work = mkdtempSync(join(tmpdir(), 'php-consumer-smoke-'));
const pkg = join(work, 'package');
const app = join(work, 'app');
const run = (cmd, args, cwd) =>
  execFileSync(cmd, args, { cwd, stdio: ['ignore', 'inherit', 'inherit'], maxBuffer: 64 * 1024 * 1024 });

try {
  mkdirSync(pkg);
  mkdirSync(app);
  const archive = execFileSync('git', ['archive', 'HEAD'], { cwd: repoRoot, maxBuffer: 256 * 1024 * 1024 });
  execFileSync('tar', ['-x', '-C', pkg], { input: archive, maxBuffer: 256 * 1024 * 1024 });

  // A path repository has no tags to read a version from, and the extracted
  // archive is not a git checkout, so the version is stated here. It is the
  // consumer's fiction, not a claim the package makes about itself.
  writeFileSync(join(app, 'composer.json'), `${JSON.stringify({
    name: 'smoke/consumer',
    description: 'Throwaway consumer of the PHP package, built by tools/php-consumer-smoke.mjs.',
    repositories: [{
      type: 'path',
      url: pkg,
      options: { symlink: false, versions: { 'emindeniz99/apple-purchase-receipt-verifier': '9999.0.0' } },
    }],
    require: { 'emindeniz99/apple-purchase-receipt-verifier': '9999.0.0' },
  }, null, 2)}\n`);

  run('composer', ['install', '--no-scripts', '--no-progress', '--no-interaction'], app);
  run('php', [
    join(repoRoot, 'tools/php-consumer-smoke.php'),
    join(app, 'vendor/autoload.php'),
    join(repoRoot, 'fixtures'),
  ], app);
} finally {
  rmSync(work, { recursive: true, force: true });
}
