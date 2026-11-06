// Every copy of certs/ must equal the repository's certs/.
//
// certs/ holds the pinned Apple roots (top-level .cer files, which
// apple-root-watch diffs against Apple's published bytes every week), the
// WWDR intermediates that sign Apple's revocation lists
// (revocation-issuers/) and the built-in revocation list (revocations.json,
// written by tools/refresh-apple-revocations.mjs). Since MIGRATION.md
// Phase 7 one full copy is expected: rust/certs, the one the core compiles
// into aprv.wasm and every wrapper runs, because a crate cannot reach
// outside its package. The wrappers carry none, and Java's main artifact
// inlines the roots as constants that its own AppleRootCertsTest pins to
// certs/ (no .cer file, so nothing here to find).
//
// The failure this prevents: someone refreshes certs/ after a watch fires
// and the copy the module is built from keeps the old anchors, issuers or
// revocations with CI fully green. Any copy that comes back is held to the
// same rule.
//
// Copies are DISCOVERED rather than listed, so a copy added later is
// covered the day it lands instead of the day someone remembers to add it
// here. A file anywhere in the repository named like a file of certs/ is a
// copy and must equal it. A directory holding a root is a full copy of
// certs/: it must hold every file of certs/, subdirectories included, and
// nothing else. A directory holding only, say, revocations.json (a
// resource of a package that needs the list and not the roots) is a
// partial copy, held to the byte comparison alone.
import { readdirSync, readFileSync } from 'node:fs';
import { basename, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('..', import.meta.url));
const canonicalDir = join(repoRoot, 'certs');

/** Every file under `dir`, as paths relative to it with / separators. */
function files(dir, prefix = '') {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) out.push(...files(join(dir, entry.name), rel));
    else out.push(rel);
  }
  return out.sort();
}

const canonicalFiles = files(canonicalDir);
const canonical = new Map(canonicalFiles.map((rel) => [rel, readFileSync(join(canonicalDir, ...rel.split('/')))]));
const roots = canonicalFiles.filter((rel) => !rel.includes('/') && rel.endsWith('.cer'));

const problems = [];
if (roots.length === 0) {
  console.error('check-cert-copies: certs/ holds no top-level .cer files, which cannot be right');
  process.exit(1);
}
// Discovery is by file name, so the names in certs/ must be unique.
const byName = new Map();
for (const rel of canonicalFiles) {
  const name = basename(rel);
  if (byName.has(name)) problems.push(`certs/ holds two files named ${name} (${byName.get(name)}, ${rel})`);
  byName.set(name, rel);
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
    } else if (byName.has(entry.name)) {
      copies.push(join(dir, entry.name));
    }
  }
}(repoRoot));

const show = (path) => relative(repoRoot, path).split(sep).join('/');
const fullCopies = new Set();
for (const path of copies) {
  const rel = byName.get(basename(path));
  if (!readFileSync(path).equals(canonical.get(rel))) problems.push(`${show(path)} differs from certs/${rel}`);
  if (roots.includes(rel)) fullCopies.add(join(path, '..'));
}

// A full copy holds all of certs/ and nothing more: a port that ships two
// anchors where the algorithm expects three fails only against whichever
// chain uses the missing one, and one that misses revocations.json or an
// issuer compiles without them.
for (const dir of fullCopies) {
  const present = files(dir);
  for (const rel of canonicalFiles) {
    if (!present.includes(rel)) problems.push(`${show(dir)} is a copy of certs/ but lacks ${rel}`);
  }
  for (const rel of present) {
    if (!canonical.has(rel)) problems.push(`${show(dir)}/${rel} is not in certs/`);
  }
}

if (problems.length > 0) {
  for (const problem of problems) console.error(`check-cert-copies: ${problem}`);
  process.exit(1);
}
const inFull = (dir) => [...fullCopies].some((full) => dir === full || dir.startsWith(full + sep));
const partial = [...new Set(copies.map((p) => join(p, '..')))].filter((d) => !inFull(d));
console.log(`check-cert-copies: OK — ${fullCopies.size} full ${fullCopies.size === 1 ? 'copy' : 'copies'} of the ${canonical.size} files of certs/` +
  `${partial.length ? ` and ${partial.length} partial copies` : ''} all match.`);
for (const dir of [...fullCopies].map(show).sort()) console.log(`  ${dir} (full)`);
for (const dir of partial.map(show).sort()) console.log(`  ${dir}`);
