// Runs the WEB smoke on Cloudflare workerd with no compatibility flags.
//
//   node runtime-smoke/run-web-workerd.mjs <workerd-spec> [compatibility-date]
//
// The date only has to be one workerd accepts; nothing in dist/web/ depends
// on a nodejs_compat-era feature, which is the property this proves. The
// default is the same floor date the node:crypto build needs, so the two
// runners are compared at the same point rather than at a friendlier one.
import { execFileSync } from 'node:child_process';
import { readFileSync, rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const [spec, date = '2024-09-23'] = process.argv.slice(2);
if (!spec) {
  console.error('usage: run-web-workerd.mjs <workerd-spec> [compatibility-date]');
  process.exit(2);
}

const here = (rel) => fileURLToPath(new URL(rel, import.meta.url));
const config = readFileSync(here('./web-workerd.capnp'), 'utf8')
  .replace(/compatibilityDate = "[^"]*"/, `compatibilityDate = "${date}"`);

// Written next to web-workerd.capnp because every `embed` path in it is
// resolved relative to the config file's own directory.
const tmp = here('./.web-workerd-run.capnp');
writeFileSync(tmp, config);
try {
  console.log(`# workerd compatibilityDate=${date} flags=(none)`);
  execFileSync('npx', ['--yes', spec, 'test', tmp], { stdio: 'inherit' });
} finally {
  rmSync(tmp, { force: true });
}
