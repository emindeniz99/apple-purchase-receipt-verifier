// Node / Bun / Deno: import the INSTALLED package by name and smoke it.
//   cd <consumer> && node run-smoke.mjs <package-name>
import { smoke } from './smoke.mjs';
import { vectors } from './vectors.mjs';
const t0 = performance.now();
const pkg = await import(process.argv[2]);
const importMs = performance.now() - t0;
const rep = smoke(pkg, vectors);
console.log(JSON.stringify({ runtime: typeof Bun !== 'undefined' ? `bun ${Bun.version}` : typeof Deno !== 'undefined' ? `deno ${Deno.version.deno}` : `node ${process.version}`, pkg: process.argv[2], importMs: Math.round(importMs * 10) / 10, ...rep }));
