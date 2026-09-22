/**
 * Apple's two verifyReceipt date renderings, `yyyy-MM-dd HH:mm:ss Etc/GMT`
 * and `yyyy-MM-dd HH:mm:ss America/Los_Angeles`, computed without Intl.
 *
 * Fastly Compute has no Intl at all, and building an Intl.DateTimeFormat
 * for every date cost most of the time spent rendering a large receipt. For
 * instants from 2007 through 9999 the Pacific offset comes from the US
 * daylight-saving rule in force since 2007: PDT (-07:00) from the second
 * Sunday of March at 02:00 PST to the first Sunday of November at 02:00
 * PDT, PST (-08:00) otherwise. That is also the rule the tz database
 * projects forward, so the strings match Intl's. Instants outside that range
 * (no App Store receipt predates 2008) are formatted through Intl, as
 * before; where Intl is missing they throw, and the endpoint answers 21009.
 */

const HOUR = 3_600_000;
const FIRST_RULE_INSTANT = Date.UTC(2007, 0, 1, 8); // 2007-01-01 00:00 PST
const LAST_RULE_INSTANT = Date.UTC(9999, 11, 31); // leaves room for the -08:00 shift

/** `yyyy-MM-dd HH:mm:ss Etc/GMT` */
export function formatGmt(date: Date): string {
  const ms = date.getTime();
  if (!inRuleRange(ms)) {
    return formatWithIntl(date, 'UTC', 'Etc/GMT');
  }
  return `${fields(ms)} Etc/GMT`;
}

/** `yyyy-MM-dd HH:mm:ss America/Los_Angeles` */
export function formatPacific(date: Date): string {
  const ms = date.getTime();
  if (!inRuleRange(ms)) {
    return formatWithIntl(date, 'America/Los_Angeles', 'America/Los_Angeles');
  }
  const year = new Date(ms - 8 * HOUR).getUTCFullYear();
  // 02:00 PST is 10:00 UTC; 02:00 PDT is 09:00 UTC.
  const dstStart = Date.UTC(year, 2, nthSunday(year, 2, 2), 10);
  const dstEnd = Date.UTC(year, 10, nthSunday(year, 10, 1), 9);
  const offset = ms >= dstStart && ms < dstEnd ? -7 * HOUR : -8 * HOUR;
  return `${fields(ms + offset)} America/Los_Angeles`;
}

function inRuleRange(ms: number): boolean {
  return ms >= FIRST_RULE_INSTANT && ms < LAST_RULE_INSTANT;
}

/** Day of the month of the nth Sunday of a month (0-based month). */
function nthSunday(year: number, month: number, n: number): number {
  const firstWeekday = new Date(Date.UTC(year, month, 1)).getUTCDay();
  return 1 + ((7 - firstWeekday) % 7) + 7 * (n - 1);
}

function two(value: number): string {
  return String(value).padStart(2, '0');
}

/** The UTC fields of `ms` as `yyyy-MM-dd HH:mm:ss`. */
function fields(ms: number): string {
  const d = new Date(ms);
  return (
    `${d.getUTCFullYear()}-${two(d.getUTCMonth() + 1)}-${two(d.getUTCDate())} ` +
    `${two(d.getUTCHours())}:${two(d.getUTCMinutes())}:${two(d.getUTCSeconds())}`
  );
}

function formatWithIntl(date: Date, timeZone: string, label: string): string {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(date);
  const get = (type: string): string => parts.find((p) => p.type === type)?.value ?? '00';
  return (
    `${get('year')}-${get('month')}-${get('day')} ` +
    `${get('hour')}:${get('minute')}:${get('second')} ${label}`
  );
}
