// Runs the two TypeScript passes at once.
//
// tsconfig.json builds dist/. tsconfig.web.json emits nothing: it re-checks
// the web entry point without @types/node, so a stray Buffer or node: import
// is a compile error there even though the main build would accept it.
// Neither reads the other's output, so running them in sequence only added
// their times together — about two seconds on every one of the CI jobs that
// runs the suite.
//
// Exits non-zero if either pass fails, and reports both rather than stopping
// at the first, so one run tells you everything that is wrong.
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const tsc = fileURLToPath(new URL('../node_modules/.bin/tsc', import.meta.url));
const passes = [
  { name: 'build', args: [] },
  { name: 'web type-check', args: ['-p', 'tsconfig.web.json'] },
];

const results = await Promise.all(passes.map(({ name, args }) => new Promise((resolve) => {
  const child = spawn(tsc, args, {
    cwd: fileURLToPath(new URL('..', import.meta.url)),
    stdio: 'inherit',
  });
  child.on('error', (error) => resolve({ name, code: 1, error }));
  child.on('close', (code) => resolve({ name, code: code ?? 1 }));
})));

// A failing pass still lets the other finish, so one run reports everything.
  const failed = results.filter((r) => r.code !== 0);
for (const { name, error } of failed) {
  console.error(`tsc ${name} failed${error ? `: ${error.message}` : ''}`);
}
process.exit(failed.length === 0 ? 0 : 1);
