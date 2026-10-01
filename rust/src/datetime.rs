//! Dates: the one form a receipt date takes, and the three renderings
//! Apple's `verifyReceipt` response gives every date.
//!
//! Three things need dates here: the `YYYY-MM-DDTHH:MM:SSZ` strings a legacy
//! receipt carries in its attributes ([`parse_receipt_date`]), the clock a
//! [`Config`](crate::Config) reads, and the renderings of the endpoint
//! (`x` in GMT, `x_ms` in epoch milliseconds and `x_pst` in US Pacific
//! time).
//!
//! The calendar and the time zone come from `jiff`; this crate does not
//! maintain calendar code. `jiff::tz::get!` compiles `America/Los_Angeles`,
//! and no other zone, into the binary from the IANA database that `jiff`
//! ships, so nothing reads `/usr/share/zoneinfo` at run time (a `FROM
//! scratch` image and the Wasm module have none) and the module carries one
//! zone rather than the database. The measurements behind the choice are in
//! `docs/evidence/2026-10-01-pacific-tz-crates.md`.
//!
//! What stays written out here is the receipt-date grammar. It is the
//! contract with the Java implementation, pinned by the shared cases, so it
//! is checked byte by byte before `jiff` sees the fields, and `jiff`'s own
//! parsers, which accept more, are not used.

use jiff::civil::{Date, DateTime, Time};
use jiff::tz::{Offset, TimeZone};
use jiff::Timestamp;
use std::time::{SystemTime, UNIX_EPOCH};

/// `America/Los_Angeles`, embedded at compile time.
static PACIFIC: TimeZone = jiff::tz::get!("America/Los_Angeles");

/// UTC−8, US Pacific standard time.
const PST_OFFSET_SECONDS: i64 = -8 * 3600;

/// `1900-01-01T00:00:00Z`. Before it [`pacific_offset_seconds`] answers PST.
const PACIFIC_FROM: i64 = -2_208_988_800;

/// `2100-01-01T00:00:00Z`. Today's daylight-saving rule (since 2007) holds
/// from long before it.
const YEAR_2100: i64 = 4_102_444_800;

/// 400 Gregorian years: 146,097 days, a whole number of weeks. The calendar,
/// the weekdays and so the current US daylight-saving rule repeat after it.
const CYCLE_SECONDS: i64 = 146_097 * 86_400;

/// The civil epoch, `1970-01-01T00:00:00`.
const EPOCH: DateTime = DateTime::constant(1970, 1, 1, 0, 0, 0, 0);

/// Milliseconds since the Unix epoch, saturating at the `i64` bounds.
#[must_use]
pub fn unix_millis_of(at: SystemTime) -> i64 {
    match at.duration_since(UNIX_EPOCH) {
        Ok(since) => i64::try_from(since.as_millis()).unwrap_or(i64::MAX),
        Err(before) => {
            i64::try_from(before.duration().as_millis()).map_or(i64::MIN, i64::wrapping_neg)
        }
    }
}

/// The UTC offset of `America/Los_Angeles`, in seconds, at an
/// epoch-millisecond instant.
///
/// The IANA database's answer from 1900 onward. It has to be right for
/// every instant, not just recent ones: the endpoint's `request_date_pst`
/// is rendered at a caller-supplied clock, which can name any instant at
/// all.
///
/// Before 1900 the answer is PST, which is what the database gives from
/// 1883-11-18 to 1918; the local mean time it gives before 1883 is not
/// used, so every instant before 1900 renders as it did when this crate
/// wrote the rules out by hand. From 2500 on (and `jiff` represents no
/// instant past 9999-12-30), the instant is moved back by whole 400-year
/// cycles into 2100-2500, where the same rule gives the same offset.
#[must_use]
pub fn pacific_offset_seconds(millis: i64) -> i64 {
    let seconds = millis.div_euclid(1000);
    if seconds < PACIFIC_FROM {
        return PST_OFFSET_SECONDS;
    }
    let seconds = if seconds >= YEAR_2100 + CYCLE_SECONDS {
        YEAR_2100 + (seconds - YEAR_2100).rem_euclid(CYCLE_SECONDS)
    } else {
        seconds
    };
    // 1900 to 2500 is inside jiff's range, so the fallback is not taken.
    Timestamp::from_second(seconds).map_or(PST_OFFSET_SECONDS, |at| {
        i64::from(PACIFIC.to_offset(at).seconds())
    })
}

/// Apple's `x` / `x_pst` rendering: `YYYY-MM-DD HH:MM:SS <label>`, with the
/// civil time taken in `offset_seconds`.
///
/// Every `i64` instant renders, as it did before `jiff`: `jiff` covers the
/// years -9999 to 9999 and the endpoint's clock reaches far past them. The
/// civil time is read within one 400-year cycle of 1970 and the cycles are
/// added back to the year, which the proleptic Gregorian calendar makes
/// exact. The year is printed with at least four characters, sign
/// included (`-001` for 2 BC).
#[must_use]
pub fn format_civil(millis: i64, offset_seconds: i64, label: &str) -> String {
    let local = millis
        .saturating_add(offset_seconds.saturating_mul(1000))
        .div_euclid(1000);
    let cycles = local.div_euclid(CYCLE_SECONDS);
    // 0 <= within < CYCLE_SECONDS: 1970 to 2370, inside jiff's range, so
    // the conversion cannot fail.
    let within = local.rem_euclid(CYCLE_SECONDS);
    let civil = Timestamp::from_second(within).map_or(EPOCH, |at| Offset::UTC.to_datetime(at));
    let year = i64::from(civil.year()) + 400 * cycles;
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} {}",
        year,
        civil.month(),
        civil.day(),
        civil.hour(),
        civil.minute(),
        civil.second(),
        label
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

/// Parses a receipt date attribute to epoch milliseconds: exactly
/// `YYYY-MM-DDTHH:MM:SSZ` and nothing else. A
/// four-digit year from 0000 to 9999, uppercase `T` and `Z`, a day that
/// exists in its month, hour 00 to 23, minute and second 00 to 59; no
/// fraction, no offset, no leap second. One grammar, so one receipt
/// decodes, and its chain is judged, the same way on every host.
///
/// The shape is checked here, byte by byte; `jiff` then refuses a month,
/// day, hour, minute or second out of range, and does the arithmetic.
#[must_use]
pub fn parse_receipt_date(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() != 20 {
        return None;
    }
    for (at, expected) in [
        (4, b'-'),
        (7, b'-'),
        (10, b'T'),
        (13, b':'),
        (16, b':'),
        (19, b'Z'),
    ] {
        if bytes.get(at) != Some(&expected) {
            return None;
        }
    }
    let digits = |from: usize, len: usize| -> Option<i16> {
        let mut value: i16 = 0;
        for byte in bytes.get(from..from + len)? {
            if !byte.is_ascii_digit() {
                return None;
            }
            value = value * 10 + i16::from(byte - b'0');
        }
        Some(value)
    };
    let two = |from: usize| -> Option<i8> { i8::try_from(digits(from, 2)?).ok() };
    let date = Date::new(digits(0, 4)?, two(5)?, two(8)?).ok()?;
    let time = Time::new(two(11)?, two(14)?, two(17)?, 0).ok()?;
    let seconds = date.to_datetime(time).duration_since(EPOCH).as_secs();
    Some(seconds * 1000)
}
