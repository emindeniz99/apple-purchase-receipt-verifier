// What makes the web build portable is a property of the emitted files, not
// of any single test: the module graph reachable from dist/web/index.js must
// import nothing but itself. These tests read that graph and check it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const distRoot = new URL('../dist/', import.meta.url);

/** Every module reachable from an entry point, and its source. */
function moduleGraph(entry) {
  const sources = new Map();
  const queue = [new URL(entry, distRoot).href];
  const specifiers = [];
  while (queue.length > 0) {
    const href = queue.pop();
    if (sources.has(href)) {
      continue;
    }
    const source = readFileSync(fileURLToPath(href), 'utf8');
    sources.set(href, source);
    for (const match of source.matchAll(/^\s*(?:import|export)[^'"]*from\s*'([^']+)'/gm)) {
      const specifier = match[1];
      specifiers.push([href, specifier]);
      if (specifier.startsWith('.')) {
        queue.push(new URL(specifier, href).href);
      }
    }
  }
  return { sources, specifiers };
}

const { sources, specifiers } = moduleGraph('web/index.js');

test('the web build imports nothing outside itself', () => {
  const foreign = specifiers.filter(([, specifier]) => !specifier.startsWith('.'));
  assert.deepEqual(
    foreign,
    [],
    `web build must have zero imports that are not relative: ${JSON.stringify(foreign)}`,
  );
});

test('the web build never mentions Buffer, process or a node: module', () => {
  for (const [href, source] of sources) {
    const name = href.slice(distRoot.href.length);
    // Comments are stripped first: the files explain what they avoid, and
    // saying "no Buffer" must not read as using one.
    const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    assert.doesNotMatch(code, /\bnode:/, name);
    assert.doesNotMatch(code, /\bBuffer\b/, name);
    assert.doesNotMatch(code, /\bprocess\b/, name);
    assert.doesNotMatch(code, /\brequire\s*\(/, name);
  }
});

// A module added to a build but not to its workerd config fails at import
// time inside the worker, which is a runtime-smoke failure — a slow, remote
// one. Both configs are checked here, the Node build's included: the two
// entry points share modules, so a change to the shared ones moves both
// graphs at once.
const WORKERD_CONFIGS = [
  ['web-workerd.capnp', 'web/index.js'],
  ['workerd.capnp', 'index.js'],
];

for (const [config, entry] of WORKERD_CONFIGS) {
  test(`${config} embeds exactly the module graph of dist/${entry}`, () => {
    const capnp = readFileSync(
      fileURLToPath(new URL(`../runtime-smoke/${config}`, import.meta.url)),
      'utf8',
    );
    const embedded = [...capnp.matchAll(/\(name = "(dist\/[^"]+)"/g)].map((m) => m[1]);
    const reachable = [...moduleGraph(entry).sources.keys()].map(
      (href) => `dist/${href.slice(distRoot.href.length)}`,
    );
    assert.deepEqual(embedded.toSorted(), reachable.toSorted());
  });
}
