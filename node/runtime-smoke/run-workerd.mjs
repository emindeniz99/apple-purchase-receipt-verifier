// Runs the workerd smoke at a given compatibility date and flag set, so CI
// can prove the floor as well as the newest date. workerd's config is a
// capnp constant, so the date is substituted into a temporary copy rather
// than passed as a flag.
//
//   node runtime-smoke/run-workerd.mjs <workerd-spec> <date> <flag>[,<flag>]
//
// The floor is 2024-09-23 with nodejs_compat: that is the date workerd made
// nodejs_compat_v2 implied, and v2 is what supplies the global Buffer this
// package's DER handling uses. Older dates work only with the explicit
// nodejs_compat_v2 flag; below that, no configuration works.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const [spec, date, flags] = process.argv.slice(2);
if (!spec || !date || !flags) {
  console.error('usage: run-workerd.mjs <workerd-spec> <date> <flags>');
  process.exit(2);
}

const here = (rel) => fileURLToPath(new URL(rel, import.meta.url));
const config = readFileSync(here('./workerd.capnp'), 'utf8')
  .replace(/compatibilityDate = "[^"]*"/, `compatibilityDate = "${date}"`)
  .replace(
    /compatibilityFlags = \[[^\]]*\]/,
    `compatibilityFlags = [${flags
      .split(',')
      .map((f) => `"${f}"`)
      .join(', ')}]`,
  );

// Written next to workerd.capnp because every `embed` path in it is
// resolved relative to the config file's own directory.
const tmp = here('./.workerd-run.capnp');
writeFileSync(tmp, config);
try {
  console.log(`# workerd compatibilityDate=${date} flags=${flags}`);
  execFileSync('npx', ['--yes', spec, 'test', tmp], { stdio: 'inherit' });
} finally {
  rmSync(tmp, { force: true });
}
