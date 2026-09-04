//! Calendar arithmetic with no dependencies and no timezone database.
//!
//! Two things need dates here: the RFC 3339 strings a legacy receipt carries
//! in its attributes, and the three renderings Apple's `verifyReceipt`
//! response gives every date (`x` in GMT, `x_ms` in epoch milliseconds and
//! `x_pst` in US Pacific time).
//!
//! `America/Los_Angeles` is implemented directly rather than read from a
//! timezone database: `chrono-tz` compiles the whole IANA database in, and
//! `jiff` reads `/usr/share/zoneinfo`, which does not exist in a `FROM
//! scratch` or distroless image — a silent runtime failure in exactly the
//! deployment shape this library targets. The rule is closed-form and is
//! unit-tested on both boundaries in both directions.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MILLIS_PER_DAY: i64 = 86_400_000;
const SECONDS_PER_DAY: i64 = 86_400;

/// A `SystemTime` `millis` milliseconds after the Unix epoch.
#[must_use]
pub fn system_time_from_millis(millis: i64) -> SystemTime {
    if millis >= 0 {
        UNIX_EPOCH + Duration::from_millis(millis.unsigned_abs())
    } else {
        UNIX_EPOCH - Duration::from_millis(millis.unsigned_abs())
    }
}

/// Milliseconds since the Unix epoch, saturating at the `i64` bounds.
#[must_use]
pub fn unix_millis_of(at: SystemTime) -> i64 {
    crate::clock::unix_millis(at)
}

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

/// ISO-8601 UTC, with a zero millisecond component dropped —
/// `2024-08-06T12:00:00Z`, `2024-08-06T12:00:00.250Z`.
#[must_use]
pub fn to_rfc3339_utc(at: SystemTime) -> String {
    to_rfc3339_utc_millis(unix_millis_of(at))
}

/// ISO-8601 UTC for an epoch-millisecond instant.
#[must_use]
pub fn to_rfc3339_utc_millis(millis: i64) -> String {
    let c = civil_from_millis(millis);
    if c.millis == 0 {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            c.year, c.month, c.day, c.hour, c.minute, c.second
        )
    } else {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            c.year, c.month, c.day, c.hour, c.minute, c.second, c.millis
        )
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
/// Exact against the IANA database for every instant from 1900 onward. The
/// four shipped ports of this library render Apple's `*_pst` fields through
/// a full time-zone database (`Intl.DateTimeFormat`, `ZoneId`, `zoneinfo`,
/// `TimeZone`); this crate has no such dependency, so the rules are written
/// out, and a port that is one hour out from the other four for some instant
/// is a real divergence — the endpoint's `request_date_pst` is rendered at a
/// caller-supplied clock, which can name any instant at all.
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

/// Apple's GMT rendering of an instant.
#[must_use]
pub fn format_etc_gmt(millis: i64) -> String {
    format_civil(millis, 0, "Etc/GMT")
}

/// Apple's US-Pacific rendering of an instant.
#[must_use]
pub fn format_pacific(millis: i64) -> String {
    format_civil(
        millis,
        pacific_offset_seconds(millis),
        "America/Los_Angeles",
    )
}

/// Parses an RFC 3339 timestamp to epoch milliseconds.
///
/// The timezone designator is **mandatory**. That is not pedantry: a naive
/// date would be read as the server's local time, and a receipt's creation
/// date is the instant its certificate chain's validity is judged at — so
/// the same receipt would verify on one host and fail on another. Java,
/// Node, Python and Swift all reject a naive date too.
#[must_use]
pub fn parse_rfc3339(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    // YYYY-MM-DDTHH:MM:SS is 19 characters, and something must follow it.
    if bytes.len() < 20 {
        return None;
    }
    let digits = |from: usize, len: usize| -> Option<i64> {
        let slice = bytes.get(from..from.checked_add(len)?)?;
        let mut value: i64 = 0;
        for byte in slice {
            if !byte.is_ascii_digit() {
                return None;
            }
            value = value.checked_mul(10)?.checked_add(i64::from(byte - b'0'))?;
        }
        Some(value)
    };
    let literal = |at: usize, expected: u8| -> bool { bytes.get(at) == Some(&expected) };
    if !(literal(4, b'-')
        && literal(7, b'-')
        && literal(10, b'T')
        && literal(13, b':')
        && literal(16, b':'))
    {
        return None;
    }
    let year = digits(0, 4)?;
    let month = digits(5, 2)?;
    let day = digits(8, 2)?;
    let hour = digits(11, 2)?;
    let minute = digits(14, 2)?;
    let second = digits(17, 2)?;
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    // RFC 3339 allows second == 60 for a leap second; no receipt carries one
    // and the other ports reject it, so this does too.
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    let mut index = 19;
    let mut millis: i64 = 0;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let start = index;
        let mut place = 0;
        while let Some(byte) = bytes.get(index) {
            if !byte.is_ascii_digit() {
                break;
            }
            if place < 3 {
                millis = millis * 10 + i64::from(byte - b'0');
                place += 1;
            }
            index += 1;
        }
        if index == start {
            return None;
        }
        while place < 3 {
            millis *= 10;
            place += 1;
        }
    }

    let offset_seconds = match bytes.get(index) {
        Some(b'Z') => {
            index += 1;
            0
        }
        Some(sign @ (b'+' | b'-')) => {
            let negative = *sign == b'-';
            if !literal(index + 3, b':') {
                return None;
            }
            let oh = digits(index + 1, 2)?;
            let om = digits(index + 4, 2)?;
            if oh > 23 || om > 59 {
                return None;
            }
            index += 6;
            let total = oh * 3600 + om * 60;
            if negative {
                -total
            } else {
                total
            }
        }
        _ => return None,
    };
    if index != bytes.len() {
        return None;
    }

    let days = days_from_civil(year, month, day);
    let seconds = days
        .checked_mul(SECONDS_PER_DAY)?
        .checked_add(hour * 3600 + minute * 60 + second)?
        .checked_sub(offset_seconds)?;
    seconds.checked_mul(1000)?.checked_add(millis)
}
