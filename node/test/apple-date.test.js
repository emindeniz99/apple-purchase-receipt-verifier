// apple-date.ts renders the verifyReceipt dates with arithmetic instead of
// Intl: Fastly Compute has no Intl at all, and an Intl.DateTimeFormat per
// date was most of the cost of rendering a large receipt. Its Pacific
// offset is the US daylight-saving rule of 2007 written out by hand, so it
// is checked here against Intl on Node, which carries the tz database, as
// the exact strings the renderer emits. A mistake in the rule, a transition
// an hour off, or a padding slip would show up as a differing string.
import test from 'node:test';
import assert from 'node:assert/strict';
import { formatGmt, formatPacific } from '../dist/apple-date.js';

// The renderer's previous formatter, verbatim except that the two
// Intl.DateTimeFormat objects are built once: this is what the output must
// still be.
const formatters = new Map();
function viaIntl(date, timeZone, label) {
  if (!formatters.has(timeZone)) {
    formatters.set(
      timeZone,
      new Intl.DateTimeFormat('en-CA', {
        timeZone,
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hourCycle: 'h23',
      }),
    );
  }
  const parts = formatters.get(timeZone).formatToParts(date);
  const get = (type) => parts.find((p) => p.type === type)?.value ?? '00';
  return (
    `${get('year')}-${get('month')}-${get('day')} ` +
    `${get('hour')}:${get('minute')}:${get('second')} ${label}`
  );
}

const HOUR = 3_600_000;
const MINUTE = 60_000;

let pdt = 0;
let pst = 0;
function check(ms) {
  const date = new Date(ms);
  const gmt = viaIntl(date, 'UTC', 'Etc/GMT');
  const pacific = viaIntl(date, 'America/Los_Angeles', 'America/Los_Angeles');
  if (formatGmt(date) !== gmt || formatPacific(date) !== pacific) {
    assert.equal(formatGmt(date), gmt, `GMT at ${ms}`);
    assert.equal(formatPacific(date), pacific, `Pacific at ${ms}`);
  }
  // Which offset Intl applied, so the test can show it crossed both.
  const shift =
    (Date.parse(`${gmt.slice(0, 19).replace(' ', 'T')}Z`) -
      Date.parse(`${pacific.slice(0, 19).replace(' ', 'T')}Z`)) /
    HOUR;
  if (shift === 7) pdt += 1;
  if (shift === 8) pst += 1;
}

test('every hour from 2008 through 2040 formats as Intl does', () => {
  pdt = 0;
  pst = 0;
  for (let ms = Date.UTC(2008, 0, 1); ms < Date.UTC(2041, 0, 1); ms += HOUR) {
    check(ms);
  }
  assert.ok(pdt > 100_000 && pst > 100_000, `crossed both offsets: pdt ${pdt}, pst ${pst}`);
});

test('the minutes and seconds around every transition from 2007 to 2040 format as Intl does', () => {
  let transitions = 0;
  for (let year = 2007; year <= 2040; year++) {
    // Intl finds the transitions itself: the hours where its offset changes.
    for (let ms = Date.UTC(year, 0, 1, 8); ms < Date.UTC(year + 1, 0, 1, 8); ms += HOUR) {
      const before = viaIntl(new Date(ms), 'America/Los_Angeles', '').slice(11, 13);
      const after = viaIntl(new Date(ms + HOUR), 'America/Los_Angeles', '').slice(11, 13);
      if ((Number(before) + 1) % 24 === Number(after)) {
        continue;
      }
      transitions += 1;
      for (let t = ms - 3 * HOUR; t <= ms + 4 * HOUR; t += MINUTE) {
        check(t);
      }
      for (let t = ms - 2 * MINUTE; t <= ms + HOUR + 2 * MINUTE; t += 1000) {
        check(t);
      }
    }
  }
  assert.equal(transitions, 2 * 34, 'two transitions a year');
});

test('random instants, the range edges and the Intl fallback format as Intl does', () => {
  // mulberry32, seeded: the same instants on every run.
  let state = 0x0a9e1eda;
  const random = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const low = Date.UTC(2007, 0, 1);
  const high = Date.UTC(9999, 11, 31);
  for (let i = 0; i < 50_000; i++) {
    check(Math.floor(low + random() * (high - low)));
  }
  const first = Date.UTC(2007, 0, 1, 8);
  const last = Date.UTC(9999, 11, 31);
  for (const ms of [
    first - 1,
    first,
    first + 1,
    last - 1,
    last,
    last + 1,
    0,
    Date.UTC(1999, 3, 4, 10),
    Date.UTC(1987, 3, 5, 10),
    Date.UTC(1969, 11, 31, 23, 59, 59, 999),
    Date.UTC(2006, 9, 29, 9),
    Date.UTC(2040, 10, 4, 9) - 1,
    Date.UTC(2040, 10, 4, 9),
  ]) {
    check(ms);
  }
});

test('an invalid date still throws, so the endpoint answers 21009', () => {
  assert.throws(() => formatGmt(new Date(NaN)), RangeError);
  assert.throws(() => formatPacific(new Date(NaN)), RangeError);
});
