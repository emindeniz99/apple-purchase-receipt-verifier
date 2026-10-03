// Reading fixtures/cases.json and the fixture files it registers, shared by
// tools/lint-cases.mjs, tools/gen-cases-manifest.mjs,
// tools/wasm-trap-host.mjs and tools/differential/cases-calls.mjs.
//
// Each function throws on a problem; a caller that collects problems or
// exits on the first one catches and reports in its own way.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

/**
 * A fixture file's logical bytes under its cases.json codec: `raw` and
 * `text` verbatim (text untrimmed: the string a client sent), `utf8`
 * trimmed, `base64` decoded with whitespace removed.
 */
export function decodeFixture(raw, codec) {
  switch (codec) {
    case 'raw':
    case 'text':
      return raw;
    case 'utf8':
      return Buffer.from(raw.toString('utf8').trim(), 'utf8');
    case 'base64':
      return Buffer.from(raw.toString('utf8').replace(/\s+/g, ''), 'base64');
    default:
      throw new Error(`unknown codec "${codec}"`);
  }
}

/**
 * The decoded bytes of the fixture `entry` registers under `id`, after
 * checking them against its contentSha256: a fixture that drifted fails
 * loudly rather than have a tool use different bytes than the vectors
 * describe.
 */
export function readFixture(fixturesDir, entry, id) {
  const where = `fixture "${id}" (${entry.path}, codec ${entry.codec})`;
  let bytes;
  try {
    bytes = decodeFixture(readFileSync(join(fixturesDir, entry.path)), entry.codec);
  } catch (e) {
    throw new Error(`${where}: ${e.message}`);
  }
  const actual = createHash('sha256').update(bytes).digest('hex');
  if (actual !== entry.contentSha256) {
    throw new Error(
      `${where} has drifted: cases.json records ${entry.contentSha256}, the decoded bytes hash to ${actual}`,
    );
  }
  return bytes;
}

// Whether JSON.parse hands a reviver each primitive's source text (Node 22
// and later).
let sourceTextSeen = false;
JSON.parse('0', (_key, value, context) => {
  sourceTextSeen = context?.source === '0';
  return value;
});

/**
 * JSON.parse that keeps an integer literal a double cannot hold as a
 * BigInt. The vectors pin a `download_id` of 2^63 - 1, which JSON.parse on
 * its own reads as 9223372036854775808, the nearest double. It needs the
 * reviver's source text, so it throws on a Node older than 22 rather than
 * round silently.
 */
export function parseJsonExact(text) {
  if (!sourceTextSeen) {
    throw new Error(
      'this Node build does not hand JSON.parse revivers the source text, so an integer ' +
        'wider than a double would be silently rounded; Node 22 or newer is required',
    );
  }
  return JSON.parse(text, (_key, value, context) =>
    typeof value === 'number' && !Number.isSafeInteger(value) && /^-?\d+$/.test(context.source)
      ? BigInt(context.source)
      : value,
  );
}
