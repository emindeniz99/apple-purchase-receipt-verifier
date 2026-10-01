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
//! zone rather than the database. The Pacific offset is the database's at
//! every instant, local mean time (−07:52:58) before 1883-11-18 included.
//! The measurements behind the choice are in
//! `docs/evidence/2026-10-01-pacific-tz-crates.md`.
//!
//! What stays written out here is the receipt-date grammar. It is the
//! contract with the Java implementation, pinned by the shared cases, so it
//! is checked byte by byte before `jiff` sees the fields, and `jiff`'s own
//! parsers, which accept more, are not used.
//!
//! An instant renders from `jiff`'s first (-9999-01-02T01:59:59Z) to the
//! grammar's last second, 9999-12-31T23:59:59Z; outside that the renderings
//! are `None`, and the endpoint answers a clock there as broken.

use jiff::civil::{Date, DateTime, Time};
use jiff::tz::{Offset, TimeZone};
use jiff::Timestamp;
use std::time::{SystemTime, UNIX_EPOCH};

/// `America/Los_Angeles`, embedded at compile time.
static PACIFIC: TimeZone = jiff::tz::get!("America/Los_Angeles");

/// The civil epoch, `1970-01-01T00:00:00`.
const EPOCH: DateTime = DateTime::constant(1970, 1, 1, 0, 0, 0, 0);

/// 9999-12-31T23:59:59.999Z, the last millisecond of the receipt grammar's
/// last second.
const LAST_MILLIS: i64 = 253_402_300_799_999;

/// Whether the renderings cover an instant: from `jiff`'s first instant to
/// [`LAST_MILLIS`]. Every receipt date [`parse_receipt_date`] accepts is
/// inside; only a caller's clock can be outside.
#[must_use]
pub fn renders(millis: i64) -> bool {
    (Timestamp::MIN.as_millisecond()..=LAST_MILLIS).contains(&millis)
}

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
/// epoch-millisecond instant: the IANA database's answer, or `None` outside
/// the instants this crate renders.
///
/// `jiff`'s last instant is 9999-12-30T22:00:00.999999999Z (room for any
/// offset to stay inside the year 9999), 26 hours before the receipt
/// grammar's last second. Later instants up to that second take the offset
/// at `jiff`'s last second, which is exact: the zone's rule puts the whole
/// of 9999-12-30 and 9999-12-31 in PST.
#[must_use]
pub fn pacific_offset_seconds(millis: i64) -> Option<i64> {
    if !renders(millis) {
        return None;
    }
    // The whole second, floored: jiff looks a timestamp up by its second
    // truncated toward zero, so before 1970 the last millisecond ahead of a
    // transition would take the new offset.
    let second = millis.div_euclid(1000).min(Timestamp::MAX.as_second());
    let at = Timestamp::from_second(second).ok()?;
    Some(i64::from(PACIFIC.to_offset(at).seconds()))
}

/// Apple's `x` / `x_pst` rendering: `YYYY-MM-DD HH:MM:SS <label>`, with the
/// civil time taken in `offset_seconds`, or `None` when that civil time is
/// outside `jiff`'s calendar (the years -9999 to 9999).
///
/// The year is printed as `jiff`'s `%Y` prints it, zero-padded to four
/// characters with the sign counted: `0000` to `9999`, and `-001` for 2 BC,
/// which the year 0000 of a receipt date reaches in Pacific time. That is
/// what the hand-written code printed too.
#[must_use]
pub fn format_civil(millis: i64, offset_seconds: i64, label: &str) -> Option<String> {
    let second = millis.div_euclid(1000);
    // jiff's last timestamp is 9999-12-30T22:00:00Z, 25:59:59 before the
    // receipt grammar's last second. The seconds past it are carried in the
    // offset instead, which jiff allows up to ±25:59:59 for exactly this:
    // every timestamp, in every offset, is a civil time in the year range.
    let at = second.min(Timestamp::MAX.as_second());
    let shift = i32::try_from(offset_seconds.checked_add(second - at)?).ok()?;
    let civil = Offset::from_seconds(shift)
        .ok()?
        .to_datetime(Timestamp::from_second(at).ok()?);
    // jiff's fields, printed as its `%Y-%m-%d %H:%M:%S` prints them (the
    // tests hold the two equal); `strftime` itself adds 237 KB to the module.
    Some(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} {label}",
        civil.year(),
        civil.month(),
        civil.day(),
        civil.hour(),
        civil.minute(),
        civil.second()
    ))
}

/// Apple's GMT rendering of an instant.
#[must_use]
pub fn format_etc_gmt(millis: i64) -> Option<String> {
    if !renders(millis) {
        return None;
    }
    format_civil(millis, 0, "Etc/GMT")
}

/// Apple's US-Pacific rendering of an instant.
#[must_use]
pub fn format_pacific(millis: i64) -> Option<String> {
    format_civil(
        millis,
        pacific_offset_seconds(millis)?,
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
