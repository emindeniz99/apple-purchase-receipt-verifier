//! Dates: the RFC 3339 form a receipt date takes, and the three renderings
//! Apple's `verifyReceipt` response gives every date.
//!
//! Three things need dates here: the RFC 3339 strings a legacy receipt
//! carries in its attributes ([`parse_receipt_date`]), the clock a
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
//! What stays written out here is the shape of an RFC 3339 `date-time`. It
//! is the contract with the Java implementation, pinned by the shared
//! cases, so it is checked byte by byte before `jiff` sees the fields, and
//! `jiff`'s own parsers, which accept more, are not used.
//!
//! An instant renders from `jiff`'s first (-9999-01-02T01:59:59Z) to the
//! last instant a receipt date can name, 9999-12-31T23:59:59.999Z; outside that the renderings
//! are `None`, and the endpoint answers a clock there as broken.

use jiff::civil::{Date, DateTime, Time};
use jiff::tz::{Offset, TimeZone};
use jiff::Timestamp;
use std::time::{SystemTime, UNIX_EPOCH};

/// `America/Los_Angeles`, embedded at compile time.
static PACIFIC: TimeZone = jiff::tz::get!("America/Los_Angeles");

/// The civil epoch, `1970-01-01T00:00:00`.
const EPOCH: DateTime = DateTime::constant(1970, 1, 1, 0, 0, 0, 0);

/// 0000-01-01T00:00:00Z, the first instant a receipt date can name.
const FIRST_MILLIS: i64 = -62_167_219_200_000;

/// 9999-12-31T23:59:59.999Z, the last instant a receipt date can name.
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
/// offset to stay inside the year 9999), 26 hours before the last second a
/// receipt date can name. Later instants up to that second take the offset
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
    // last second a receipt date can name. The seconds past it are carried in the
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

/// Parses a receipt date attribute to epoch milliseconds: an RFC 3339
/// `date-time` (§5.6), which is what Apple documents these attributes to
/// be (owner, Q68, 2026-10-06).
///
/// - A four-digit year 0000 to 9999 and a day that exists in its month;
///   hours 00 to 23, minutes 00 to 59, seconds 00 to 60.
/// - `T` and `Z` in either case (§5.6 NOTE); no other separator.
/// - A fraction of any length after a `.`, truncated to the millisecond:
///   the digits after the third are dropped, so the instant is floored.
/// - `Z` or a numeric offset `±hh:mm` (hours 00 to 23, minutes 00 to 59),
///   subtracted to give UTC; `-00:00` is UTC.
/// - A leap second, second 60, is read as second 59 with its fraction kept,
///   as `jiff`'s own parser reads it; the instants do not count leap
///   seconds.
/// - The instant must lie in 0000-01-01T00:00:00Z to
///   9999-12-31T23:59:59.999Z, where every rendering is defined.
///
/// Anything else is `None`. The shape is checked here, byte by byte, since
/// neither `jiff` nor `java.time` has a parser for exactly this language
/// (each accepts its own superset and stops at nine fraction digits);
/// `jiff` refuses a month, day, hour, minute or second out of range and
/// does the calendar arithmetic.
#[must_use]
pub fn parse_receipt_date(text: &str) -> Option<i64> {
    let (head, mut rest) = text.as_bytes().split_at_checked(19)?;
    let [y1, y2, y3, y4, b'-', mo1, mo2, b'-', d1, d2, t, h1, h2, b':', mi1, mi2, b':', s1, s2] =
        *<&[u8; 19]>::try_from(head).ok()?
    else {
        return None;
    };
    if !t.eq_ignore_ascii_case(&b'T') {
        return None;
    }
    let digits = |field: &[u8]| -> Option<i16> {
        field.iter().try_fold(0i16, |value, byte| {
            byte.is_ascii_digit()
                .then(|| value * 10 + i16::from(byte - b'0'))
        })
    };
    let two = |tens: u8, units: u8| -> Option<i8> { i8::try_from(digits(&[tens, units])?).ok() };
    let mut millis = 0;
    if let Some(fraction) = rest.strip_prefix(b".") {
        let len = fraction
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        let (fraction, after) = fraction.split_at_checked(len)?;
        if fraction.is_empty() {
            return None;
        }
        millis = fraction
            .iter()
            .chain(b"00")
            .take(3)
            .fold(0, |value, byte| value * 10 + i64::from(byte - b'0'));
        rest = after;
    }
    let offset_minutes = match rest {
        [z] if z.eq_ignore_ascii_case(&b'Z') => 0,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            let (hours, minutes) = (digits(&[*h1, *h2])?, digits(&[*m1, *m2])?);
            if hours > 23 || minutes > 59 {
                return None;
            }
            let minutes = i64::from(hours * 60 + minutes);
            if *sign == b'-' {
                -minutes
            } else {
                minutes
            }
        }
        _ => return None,
    };
    let second = two(s1, s2)?;
    if second > 60 {
        return None;
    }
    let date = Date::new(digits(&[y1, y2, y3, y4])?, two(mo1, mo2)?, two(d1, d2)?).ok()?;
    let time = Time::new(two(h1, h2)?, two(mi1, mi2)?, second.min(59), 0).ok()?;
    let seconds = date.to_datetime(time).duration_since(EPOCH).as_secs() - offset_minutes * 60;
    let instant = seconds * 1000 + millis;
    (FIRST_MILLIS..=LAST_MILLIS)
        .contains(&instant)
        .then_some(instant)
}
