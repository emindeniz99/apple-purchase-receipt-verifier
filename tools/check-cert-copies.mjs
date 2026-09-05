// Every copy of the pinned Apple roots must equal the repository's certs/.
//
// The roots live in certs/ and apple-root-watch diffs that directory against
// Apple's published bytes every week. Most ports then carry their own copy,
// because a package has to ship the anchors it uses; several compile them
// into source as well. That is three links in a chain, and only the middle
// one was being checked.
//
// The failure this prevents: someone refreshes certs/ after the watch fires,
// updates most ports, misses one, and that port keeps shipping the old
// anchors with CI fully green. Its own generated file still matches its own
// stale copy, so a per-port regenerate-and-diff cannot see it.
//
// Copies are DISCOVERED rather than listed, so a port added later is covered
// the day it lands instead of the day someone remembers to add it here.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('..', import.meta.url));
const canonicalDir = join(repoRoot, 'certs');
const canonical = new Map(
  readdirSync(canonicalDir)
    .filter((name) => name.endsWith('.cer'))
    .map((name) => [name, readFileSync(join(canonicalDir, name))]),
);

if (canonical.size === 0) {
  console.error('check-cert-copies: certs/ holds no .cer files, which cannot be right');
  process.exit(1);
}

// Directories that are not ours to police: dependencies, build output, and
// the vendored test fixtures, whose certificates are deliberately not Apple's.
const SKIP = new Set([
  '.git', 'node_modules', 'dist', 'build', '.build', 'target', 'bin', 'obj',
  'vendor', '.venv', '__pycache__', 'fixtures',
]);

const copies = [];
(function walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (SKIP.has(entry.name)) continue;
      const child = join(dir, entry.name);
      if (child === canonicalDir) continue;
      walk(child);
    } else if (canonical.has(entry.name)) {
      copies.push(join(dir, entry.name));
    }
  }
}(repoRoot));

const problems = [];
const seenDirs = new Set();
for (const path of copies) {
  seenDirs.add(relative(repoRoot, join(path, '..')));
  if (!readFileSync(path).equals(canonical.get(path.split('/').pop()))) {
    problems.push(`${relative(repoRoot, path)} differs from certs/`);
  }
}

// A directory holding some of the roots but not all of them is its own bug:
// a port that ships two anchors where the algorithm expects three fails only
// against whichever chain uses the missing one.
for (const dir of seenDirs) {
  const present = readdirSync(join(repoRoot, dir)).filter((n) => canonical.has(n));
  if (present.length !== canonical.size) {
    const missing = [...canonical.keys()].filter((n) => !present.includes(n));
    problems.push(`${dir} carries ${present.length} of ${canonical.size} roots, missing ${missing.join(', ')}`);
  }
}

if (problems.length > 0) {
  for (const problem of problems) console.error(`check-cert-copies: ${problem}`);
  process.exit(1);
}
console.log(`check-cert-copies: OK — ${seenDirs.size} copies of ${canonical.size} roots all match certs/.`);
for (const dir of [...seenDirs].sort()) console.log(`  ${dir}`);
