// Copied verbatim from apple-purchase-receipt-verifier rust/src/datetime.rs
// (lines 18-19, 42-122, 148-304) for the tz-spike. Not edited.
#![allow(dead_code)]
const MILLIS_PER_DAY: i64 = 86_400_000;
const SECONDS_PER_DAY: i64 = 86_400;
/// Days since 1970-01-01 for a proleptic-Gregorian civil date.
///
/// Howard Hinnant's `days_from_civil`.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The civil date `days` days after 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Day of week for a day number, 0 = Sunday.
fn weekday_from_days(days: i64) -> i64 {
    if days >= -4 {
        (days + 4) % 7
    } else {
        (days + 5) % 7 + 6
    }
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// A civil date and time, as rendered in some fixed UTC offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Civil {
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
    millis: i64,
}

fn civil_from_millis(millis: i64) -> Civil {
    let days = millis.div_euclid(MILLIS_PER_DAY);
    let rem = millis.rem_euclid(MILLIS_PER_DAY);
    let (year, month, day) = civil_from_days(days);
    Civil {
        year,
        month,
        day,
        hour: rem / 3_600_000,
        minute: (rem / 60_000) % 60,
        second: (rem / 1_000) % 60,
        millis: rem % 1_000,
    }
}
/// UTC−8, US Pacific standard time.
pub const PST_OFFSET_SECONDS: i64 = -8 * 3600;
/// UTC−7, US Pacific daylight time.
pub const PDT_OFFSET_SECONDS: i64 = -7 * 3600;

/// `1967-01-01T00:00:00Z`. From here on the transitions follow rules simple
/// enough to state in closed form; before it they do not.
const REGULAR_RULES_FROM: i64 = -94_694_400;

/// Every US-Pacific offset change from 1900 up to [`REGULAR_RULES_FROM`], as
/// `(UTC second, offset)`.
///
/// This era is a table rather than a rule because it genuinely is not one:
/// wartime daylight time ran continuously from February 1942 to September
/// 1945, 1948 was a single year of it, and from 1950 to 1966 the start and
/// end were 01:00 local rather than the 02:00 every later rule uses — with
/// the end moving from September to October in 1962. Nothing here can be
/// derived; it is transcribed from the IANA database, and
/// `tests/data/pacific-transitions.txt` re-checks every boundary in it.
const PRE_1967_TRANSITIONS: [(i64, i64); 42] = [
    (-1_633_269_600, PDT_OFFSET_SECONDS), // 1918-03-31 10:00:00Z
    (-1_615_129_200, PST_OFFSET_SECONDS), // 1918-10-27 09:00:00Z
    (-1_601_820_000, PDT_OFFSET_SECONDS), // 1919-03-30 10:00:00Z
    (-1_583_679_600, PST_OFFSET_SECONDS), // 1919-10-26 09:00:00Z
    (-880_207_200, PDT_OFFSET_SECONDS),   // 1942-02-09 10:00:00Z
    (-765_385_200, PST_OFFSET_SECONDS),   // 1945-09-30 09:00:00Z
    (-687_967_140, PDT_OFFSET_SECONDS),   // 1948-03-14 10:01:00Z
    (-662_655_600, PST_OFFSET_SECONDS),   // 1949-01-01 09:00:00Z
    (-620_838_000, PDT_OFFSET_SECONDS),   // 1950-04-30 09:00:00Z
    (-608_137_200, PST_OFFSET_SECONDS),   // 1950-09-24 09:00:00Z
    (-589_388_400, PDT_OFFSET_SECONDS),   // 1951-04-29 09:00:00Z
    (-576_082_800, PST_OFFSET_SECONDS),   // 1951-09-30 09:00:00Z
    (-557_938_800, PDT_OFFSET_SECONDS),   // 1952-04-27 09:00:00Z
    (-544_633_200, PST_OFFSET_SECONDS),   // 1952-09-28 09:00:00Z
    (-526_489_200, PDT_OFFSET_SECONDS),   // 1953-04-26 09:00:00Z
    (-513_183_600, PST_OFFSET_SECONDS),   // 1953-09-27 09:00:00Z
    (-495_039_600, PDT_OFFSET_SECONDS),   // 1954-04-25 09:00:00Z
    (-481_734_000, PST_OFFSET_SECONDS),   // 1954-09-26 09:00:00Z
    (-463_590_000, PDT_OFFSET_SECONDS),   // 1955-04-24 09:00:00Z
    (-450_284_400, PST_OFFSET_SECONDS),   // 1955-09-25 09:00:00Z
    (-431_535_600, PDT_OFFSET_SECONDS),   // 1956-04-29 09:00:00Z
    (-418_230_000, PST_OFFSET_SECONDS),   // 1956-09-30 09:00:00Z
    (-400_086_000, PDT_OFFSET_SECONDS),   // 1957-04-28 09:00:00Z
    (-386_780_400, PST_OFFSET_SECONDS),   // 1957-09-29 09:00:00Z
    (-368_636_400, PDT_OFFSET_SECONDS),   // 1958-04-27 09:00:00Z
    (-355_330_800, PST_OFFSET_SECONDS),   // 1958-09-28 09:00:00Z
    (-337_186_800, PDT_OFFSET_SECONDS),   // 1959-04-26 09:00:00Z
    (-323_881_200, PST_OFFSET_SECONDS),   // 1959-09-27 09:00:00Z
    (-305_737_200, PDT_OFFSET_SECONDS),   // 1960-04-24 09:00:00Z
    (-292_431_600, PST_OFFSET_SECONDS),   // 1960-09-25 09:00:00Z
    (-273_682_800, PDT_OFFSET_SECONDS),   // 1961-04-30 09:00:00Z
    (-260_982_000, PST_OFFSET_SECONDS),   // 1961-09-24 09:00:00Z
    (-242_233_200, PDT_OFFSET_SECONDS),   // 1962-04-29 09:00:00Z
    (-226_508_400, PST_OFFSET_SECONDS),   // 1962-10-28 09:00:00Z
    (-210_783_600, PDT_OFFSET_SECONDS),   // 1963-04-28 09:00:00Z
    (-195_058_800, PST_OFFSET_SECONDS),   // 1963-10-27 09:00:00Z
    (-179_334_000, PDT_OFFSET_SECONDS),   // 1964-04-26 09:00:00Z
    (-163_609_200, PST_OFFSET_SECONDS),   // 1964-10-25 09:00:00Z
    (-147_884_400, PDT_OFFSET_SECONDS),   // 1965-04-25 09:00:00Z
    (-131_554_800, PST_OFFSET_SECONDS),   // 1965-10-31 09:00:00Z
    (-116_434_800, PDT_OFFSET_SECONDS),   // 1966-04-24 09:00:00Z
    (-100_105_200, PST_OFFSET_SECONDS),   // 1966-10-30 09:00:00Z
];

/// The UTC offset of `America/Los_Angeles`, in seconds, at an
/// epoch-millisecond instant.
///
/// Exact against the IANA database for every instant from 1900 onward. This
/// crate has no time-zone database, so the rules are written out, and they
/// have to be right for every instant, not just recent ones: the
/// endpoint's `request_date_pst` is rendered at a caller-supplied clock,
/// which can name any instant at all.
///
/// The rules, from 1967 on:
///
/// - since 2007: PDT from the second Sunday in March at 02:00 local standard
///   time to the first Sunday in November at 02:00 local daylight time;
/// - 1987 to 2006: first Sunday in April to last Sunday in October;
/// - 1976 to 1986, and 1967 to 1973: last Sunday in April to last Sunday in
///   October;
/// - 1975: 23 February to the last Sunday in October;
/// - 1974: 6 January to the last Sunday in October. The 1974 and 1975 dates
///   are the Emergency Daylight Saving Time Energy Conservation Act, not a
///   pattern.
///
/// Before 1967, [`PRE_1967_TRANSITIONS`]. Before 1900 the answer is PST,
/// which is what the IANA database gives for 1883-11-18 onward; the local
/// mean time it gives before *that* is out of scope and no caller can reach
/// it with an Apple date.
///
/// US daylight-saving law is the one thing that can make this wrong. It is
/// one function, and changing it is a patch release.
#[must_use]
pub fn pacific_offset_seconds(millis: i64) -> i64 {
    let seconds = millis.div_euclid(1000);
    if seconds < REGULAR_RULES_FROM {
        let mut offset = PST_OFFSET_SECONDS;
        for (at, value) in PRE_1967_TRANSITIONS {
            if seconds < at {
                break;
            }
            offset = value;
        }
        return offset;
    }
    let year = civil_from_millis(millis).year;
    // Transitions are expressed in UTC: 02:00 local standard time is 10:00
    // UTC, and 02:00 local daylight time is 09:00 UTC.
    let (start_month, start_day, end_month, end_day) = if year >= 2007 {
        (
            3,
            nth_weekday(year, 3, 0, 2),
            11,
            nth_weekday(year, 11, 0, 1),
        )
    } else if year >= 1987 {
        (4, nth_weekday(year, 4, 0, 1), 10, last_weekday(year, 10, 0))
    } else if year == 1975 {
        (2, 23, 10, last_weekday(year, 10, 0))
    } else if year == 1974 {
        (1, 6, 10, last_weekday(year, 10, 0))
    } else {
        (4, last_weekday(year, 4, 0), 10, last_weekday(year, 10, 0))
    };
    let start = days_from_civil(year, start_month, start_day) * SECONDS_PER_DAY + 10 * 3600;
    let end = days_from_civil(year, end_month, end_day) * SECONDS_PER_DAY + 9 * 3600;
    if seconds >= start && seconds < end {
        PDT_OFFSET_SECONDS
    } else {
        PST_OFFSET_SECONDS
    }
}

/// Day-of-month of the `n`th `weekday` (0 = Sunday) of a month, 1-based `n`.
fn nth_weekday(year: i64, month: i64, weekday: i64, n: i64) -> i64 {
    let first = days_from_civil(year, month, 1);
    let shift = (weekday - weekday_from_days(first)).rem_euclid(7);
    1 + shift + (n - 1) * 7
}

/// Day-of-month of the last `weekday` (0 = Sunday) of a month.
fn last_weekday(year: i64, month: i64, weekday: i64) -> i64 {
    let last = days_in_month(year, month);
    let last_days = days_from_civil(year, month, last);
    last - (weekday_from_days(last_days) - weekday).rem_euclid(7)
}

/// Apple's `x` / `x_pst` rendering: `YYYY-MM-DD HH:MM:SS <label>`, with the
/// civil time taken in `offset_seconds`.
#[must_use]
pub fn format_civil(millis: i64, offset_seconds: i64, label: &str) -> String {
    let c = civil_from_millis(millis.saturating_add(offset_seconds.saturating_mul(1000)));
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} {}",
        c.year, c.month, c.day, c.hour, c.minute, c.second, label
    )
}
