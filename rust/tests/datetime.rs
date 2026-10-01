//! Dates: the grammar a receipt date attribute must obey, and the two
//! renderings Apple's `verifyReceipt` response uses.
//!
//! The US-Pacific vectors below were generated from Python's `zoneinfo`
//! (the IANA database) rather than from this implementation, so they are not
//! self-referential. They cover both transitions in both directions under
//! both the pre-2007 and the current US rules.
//!
//! The differential tests at the end hold the jiff-based code to the
//! hand-written code it replaced (`hand_written_datetime/`), output for
//! output.

mod hand_written_datetime;

use apple_purchase_receipt_verifier::__internal::datetime::{
    format_civil, format_etc_gmt, format_pacific, pacific_offset_seconds, parse_receipt_date,
    unix_millis_of,
};
use hand_written_datetime as old;
use std::time::{Duration, UNIX_EPOCH};

/// `(epoch millis, expected US-Pacific rendering)`, from IANA via
/// `zoneinfo`.
const PACIFIC_VECTORS: [(i64, &str); 21] = [
    // 2024, current rule: DST begins on the second Sunday in March at 02:00
    // local standard time — 10:00 UTC — and 02:00 never happens.
    (1_710_064_799_000, "2024-03-10 01:59:59 America/Los_Angeles"),
    (1_710_064_800_000, "2024-03-10 03:00:00 America/Los_Angeles"),
    // and ends on the first Sunday in November at 02:00 local daylight time
    // — 09:00 UTC — so 01:00 happens twice.
    (1_730_624_399_000, "2024-11-03 01:59:59 America/Los_Angeles"),
    (1_730_624_400_000, "2024-11-03 01:00:00 America/Los_Angeles"),
    // 2025, both transitions.
    (1_741_514_399_000, "2025-03-09 01:59:59 America/Los_Angeles"),
    (1_741_514_400_000, "2025-03-09 03:00:00 America/Los_Angeles"),
    (1_762_073_999_000, "2025-11-02 01:59:59 America/Los_Angeles"),
    (1_762_074_000_000, "2025-11-02 01:00:00 America/Los_Angeles"),
    // 2006, the pre-2007 rule: first Sunday in April to last Sunday in
    // October. No genuine receipt reaches it — the App Store opened in
    // 2008 — but the function is total and this is what makes it so.
    (1_143_971_999_000, "2006-04-02 01:59:59 America/Los_Angeles"),
    (1_143_972_000_000, "2006-04-02 03:00:00 America/Los_Angeles"),
    (1_162_112_399_000, "2006-10-29 01:59:59 America/Los_Angeles"),
    (1_162_112_400_000, "2006-10-29 01:00:00 America/Los_Angeles"),
    // 2007, the first year of the current rule.
    (1_173_607_199_000, "2007-03-11 01:59:59 America/Los_Angeles"),
    (1_173_607_200_000, "2007-03-11 03:00:00 America/Los_Angeles"),
    (1_194_166_799_000, "2007-11-04 01:59:59 America/Los_Angeles"),
    (1_194_166_800_000, "2007-11-04 01:00:00 America/Los_Angeles"),
    // The two values fixtures/cases.json pins, in both seasons.
    (1_722_945_600_000, "2024-08-06 05:00:00 America/Los_Angeles"),
    (1_735_689_600_000, "2024-12-31 16:00:00 America/Los_Angeles"),
    // Ordinary days either side, including one past 2038.
    (929_448_000_000, "1999-06-15 05:00:00 America/Los_Angeles"),
    (2_161_814_400_000, "2038-07-03 17:00:00 America/Los_Angeles"),
    (1_768_465_800_000, "2026-01-15 00:30:00 America/Los_Angeles"),
];

#[test]
fn the_pacific_rendering_matches_the_iana_database() {
    for (millis, expected) in PACIFIC_VECTORS {
        assert_eq!(format_pacific(millis), expected, "at {millis}");
    }
}

#[test]
fn the_pacific_offset_is_minus_seven_or_minus_eight() {
    for (millis, expected) in PACIFIC_VECTORS {
        let offset = pacific_offset_seconds(millis);
        assert!(
            offset == -7 * 3600 || offset == -8 * 3600,
            "offset {offset} at {millis}"
        );
        let daylight = expected.contains("03:00:00") || offset == -7 * 3600;
        assert_eq!(daylight, offset == -7 * 3600);
    }
}

#[test]
fn the_transition_is_exact_to_the_second() {
    // One second either side of the 2024 spring-forward instant.
    assert_eq!(pacific_offset_seconds(1_710_064_799_999), -8 * 3600);
    assert_eq!(pacific_offset_seconds(1_710_064_800_000), -7 * 3600);
    // And of the autumn fall-back instant.
    assert_eq!(pacific_offset_seconds(1_730_624_399_999), -7 * 3600);
    assert_eq!(pacific_offset_seconds(1_730_624_400_000), -8 * 3600);
}

/// This used to assert PST for the same instant, on the grounds that the
/// App Store did not exist in 1980 so the answer need only be total. It is
/// reachable — `request_date_pst` is rendered at a caller-supplied clock —
/// and the four shipped ports all answer PDT here, so "total" was not
/// enough and the old assertion was the bug written down.
#[test]
fn summer_1980_is_daylight_time_not_standard_time() {
    // 1980-07-01T12:00:00Z, inside the 1980 DST window (27 April to
    // 26 October).
    assert_eq!(pacific_offset_seconds(331_214_400_000), -7 * 3600);
}

#[test]
fn the_gmt_rendering_is_apples_etc_gmt_form() {
    assert_eq!(
        format_etc_gmt(1_722_945_600_000),
        "2024-08-06 12:00:00 Etc/GMT"
    );
    assert_eq!(format_etc_gmt(0), "1970-01-01 00:00:00 Etc/GMT");
    assert_eq!(
        format_etc_gmt(1_735_689_600_000),
        "2025-01-01 00:00:00 Etc/GMT"
    );
}

#[test]
fn system_time_round_trips_through_epoch_millis() {
    for millis in [
        0i64,
        1,
        -1,
        1_000,
        -1_000,
        1_722_945_600_000,
        -2_208_988_800_000, // 1900-01-01
        4_070_908_800_000,  // 2099-01-01
    ] {
        let at = if millis >= 0 {
            UNIX_EPOCH + Duration::from_millis(millis.unsigned_abs())
        } else {
            UNIX_EPOCH - Duration::from_millis(millis.unsigned_abs())
        };
        assert_eq!(unix_millis_of(at), millis, "at {millis}");
    }
}

/// The receipt date grammar (owner, 2026-09-27, Q20a): exactly
/// `YYYY-MM-DDTHH:MM:SSZ`, at every edge of it.
#[test]
fn a_receipt_date_is_exactly_the_one_form() {
    assert_eq!(
        parse_receipt_date("2024-08-06T12:00:00Z"),
        Some(1_722_945_600_000)
    );
    assert_eq!(
        parse_receipt_date("0000-01-01T00:00:00Z"),
        Some(-62_167_219_200_000)
    );
    assert_eq!(
        parse_receipt_date("9999-12-31T23:59:59Z"),
        Some(253_402_300_799_000)
    );
    assert!(parse_receipt_date("2024-02-29T00:00:00Z").is_some());
    assert!(parse_receipt_date("2000-02-29T00:00:00Z").is_some());
    assert!(
        parse_receipt_date("0000-02-29T00:00:00Z").is_some(),
        "0000 is a leap year"
    );
    for text in [
        "2024-08-06t12:00:00Z",
        "2024-08-06T12:00:00z",
        "2024-08-06T12:00:00.000Z",
        "2024-08-06T12:00:00.5Z",
        "2024-08-06T12:00:00+00:00",
        "2024-08-06T12:00:00-07:00",
        "2024-08-06T12:00:00",
        "2024-08-06T12:00:60Z",
        "2024-08-06T12:60:00Z",
        "2024-08-06T24:00:00Z",
        "2023-02-29T00:00:00Z",
        "1900-02-29T00:00:00Z",
        "2024-04-31T00:00:00Z",
        "2024-00-06T12:00:00Z",
        "2024-13-06T12:00:00Z",
        "2024-08-00T12:00:00Z",
        "10000-01-01T00:00:00Z",
        "+2024-08-06T12:00:00Z",
        "-0001-08-06T12:00:00Z",
        "2024-08-06 12:00:00Z",
        " 2024-08-06T12:00:00Z",
        "2024-08-06T12:00:00Z ",
        "2024-8-06T12:00:00Z",
        "",
    ] {
        assert!(
            parse_receipt_date(text).is_none(),
            "{text:?} must be refused"
        );
    }
}

#[test]
fn parse_and_render_round_trip_across_a_century() {
    // Every first-of-month from 1970 to 2070: the civil-date arithmetic has
    // no calendar it can quietly get wrong.
    for year in 1970..2070 {
        for month in 1..=12 {
            let text = format!("{year:04}-{month:02}-01T00:00:00Z");
            let millis = parse_receipt_date(&text).unwrap_or_else(|| panic!("{text}"));
            assert_eq!(
                format_etc_gmt(millis),
                format!("{year:04}-{month:02}-01 00:00:00 Etc/GMT")
            );
        }
    }
}

#[test]
fn every_day_of_2024_round_trips() {
    let mut millis = parse_receipt_date("2024-01-01T00:00:00Z").unwrap();
    let end = parse_receipt_date("2025-01-01T00:00:00Z").unwrap();
    let mut days = 0;
    while millis < end {
        let gmt = format_etc_gmt(millis);
        let text = format!("{}Z", gmt.trim_end_matches(" Etc/GMT").replace(' ', "T"));
        assert_eq!(parse_receipt_date(&text), Some(millis), "{text}");
        // And the Pacific rendering never produces an impossible clock face.
        let pacific = format_pacific(millis);
        assert!(pacific.ends_with(" America/Los_Angeles"), "{pacific}");
        millis += 86_400_000;
        days += 1;
    }
    assert_eq!(days, 366, "2024 is a leap year");
}

/// Every US-Pacific offset transition from 1900 to 2100, checked at the
/// second before it takes effect and at the second it does.
///
/// The vectors in `tests/data/pacific-transitions.txt` come from the IANA
/// database — the same source the other four ports render `*_pst` from
/// (`Intl.DateTimeFormat`, `ZoneId`, `zoneinfo`, `TimeZone`) — so this is
/// the test that keeps this crate's Pacific offsets honest against them.
/// Regenerate with:
///
/// ```text
/// python3 -c "$(cat <<'PY'
/// from zoneinfo import ZoneInfo
/// import datetime
/// tz = ZoneInfo('America/Los_Angeles')
/// # scan hourly 1900..2100, bisect each change to the exact second,
/// # print: utc_second offset_before offset_after
/// PY
/// )"
/// ```
#[test]
fn the_us_pacific_rules_match_the_iana_database_at_every_transition() {
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/pacific-transitions.txt"),
    )
    .expect("pacific-transitions.txt");
    let mut checked = 0usize;
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let at: i64 = fields.next().unwrap().parse().unwrap();
        let before: i64 = fields.next().unwrap().parse().unwrap();
        let after: i64 = fields.next().unwrap().parse().unwrap();
        assert_eq!(
            pacific_offset_seconds((at - 1) * 1000),
            before,
            "one second before the transition at {at}"
        );
        assert_eq!(
            pacific_offset_seconds(at * 1000),
            after,
            "at the transition at {at}"
        );
        checked += 1;
    }
    assert!(
        checked > 300,
        "expected the full transition table, got {checked}"
    );
}

/// The pre-1987 branch used to short-circuit to PST year-round, which made
/// every `*_pst` string between 1970-04-26 and 1986-10-26 one hour earlier
/// than the four shipped ports render it. `request_date_pst` is produced at
/// a caller-supplied clock with no lower bound, so the branch is reachable.
#[test]
fn pre_1987_daylight_time_is_observed() {
    // 1970-04-26T10:00:00Z is the first instant of PDT in 1970.
    let at = parse_receipt_date("1970-04-26T10:00:00Z").unwrap();
    assert_eq!(
        format_pacific(at),
        "1970-04-26 03:00:00 America/Los_Angeles"
    );
    assert_eq!(
        format_pacific(at - 1000),
        "1970-04-26 01:59:59 America/Los_Angeles"
    );
    // The Emergency Daylight Saving Time Act years are not the usual rule.
    let jan_1974 = parse_receipt_date("1974-01-06T10:00:00Z").unwrap();
    assert_eq!(pacific_offset_seconds(jan_1974), -7 * 3600);
    assert_eq!(pacific_offset_seconds(jan_1974 - 1000), -8 * 3600);
    let feb_1975 = parse_receipt_date("1975-02-23T10:00:00Z").unwrap();
    assert_eq!(pacific_offset_seconds(feb_1975), -7 * 3600);
    assert_eq!(pacific_offset_seconds(feb_1975 - 1000), -8 * 3600);
    // Wartime daylight time ran continuously for three and a half years.
    let wartime = parse_receipt_date("1943-07-01T12:00:00Z").unwrap();
    assert_eq!(pacific_offset_seconds(wartime), -7 * 3600);
    // 1950-1966 switched at 01:00 local, not 02:00.
    let y1950 = parse_receipt_date("1950-04-30T09:00:00Z").unwrap();
    assert_eq!(pacific_offset_seconds(y1950), -7 * 3600);
    assert_eq!(pacific_offset_seconds(y1950 - 1000), -8 * 3600);
}

// --- the jiff-based code against the hand-written code it replaced ------

/// 1900-01-01T00:00:00Z and 2100-01-01T00:00:00Z.
const FROM_1900: i64 = -2_208_988_800;
const TO_2100: i64 = 4_102_444_800;

/// Every offset change in `tests/data/pacific-transitions.txt`, in seconds.
fn transitions() -> Vec<i64> {
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/pacific-transitions.txt"),
    )
    .expect("pacific-transitions.txt");
    text.lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .map(|line| line.split_whitespace().next().unwrap().parse().unwrap())
        .collect()
}

/// Instants whose renderings must not change by a byte: both transitions of
/// 1950, 1998, 2007 and 2026 (the second before, the second of, and the
/// last millisecond before each), the epoch, the receipt grammar's two
/// ends, the 1900 edge of the Pacific rules, and the `i64` extremes a
/// caller's clock can reach.
#[test]
fn the_renderings_are_byte_identical_to_the_hand_written_code() {
    let mut instants: Vec<i64> = Vec::new();
    for at in [
        -620_838_000,  // 1950-04-30T09:00:00Z, PDT from 01:00 local
        -608_137_200,  // 1950-09-24T09:00:00Z
        891_770_400,   // 1998-04-05T10:00:00Z
        909_306_000,   // 1998-10-25T09:00:00Z
        1_173_607_200, // 2007-03-11T10:00:00Z, the first year of today's rule
        1_194_166_800, // 2007-11-04T09:00:00Z
        1_772_964_000, // 2026-03-08T10:00:00Z
        1_793_523_600, // 2026-11-01T09:00:00Z
    ] {
        assert_ne!(
            old::pacific_offset_seconds((at - 1) * 1000),
            old::pacific_offset_seconds(at * 1000),
            "{at} is a transition"
        );
        instants.extend([(at - 1) * 1000, at * 1000 - 1, at * 1000, (at + 1) * 1000]);
    }
    instants.extend([
        0,
        -1,
        1,
        FROM_1900 * 1000 - 1,
        FROM_1900 * 1000,
        -2_717_640_000_000,  // 1883-11-18T20:00:00Z, the database's LMT to PST
        -62_167_219_200_000, // 0000-01-01T00:00:00Z, renders in 2 BC as -001
        -62_167_219_200_001,
        253_402_300_799_000, // 9999-12-31T23:59:59Z
        253_402_300_799_999,
        253_402_300_800_000, // 10000-01-01T00:00:00Z, past jiff's calendar
        16_725_225_600_000,  // 2500-01-01T00:00:00Z, the 400-year fold
        16_725_225_599_999,
        16_741_036_800_000, // 2500-07-03, PDT after the fold
        16_756_329_600_000, // 2500-12-27, PST after the fold
        1_000_000_000_000_000,
        -1_000_000_000_000_000,
        i64::MAX,
        i64::MAX - 1,
        i64::MIN,
        i64::MIN + 1,
    ]);
    for millis in instants {
        assert_eq!(
            format_etc_gmt(millis),
            old::format_etc_gmt(millis),
            "GMT at {millis}"
        );
        assert_eq!(
            format_pacific(millis),
            old::format_pacific(millis),
            "Pacific at {millis}"
        );
        assert_eq!(
            pacific_offset_seconds(millis),
            old::pacific_offset_seconds(millis),
            "offset at {millis}"
        );
        for offset in [-12 * 3600, 14 * 3600, i64::MIN, i64::MAX] {
            assert_eq!(
                format_civil(millis, offset, "X"),
                old::format_civil(millis, offset, "X"),
                "civil at {millis} offset {offset}"
            );
        }
    }
    assert_eq!(
        format_pacific(-62_167_219_200_000),
        "-001-12-31 16:00:00 America/Los_Angeles"
    );
    assert_eq!(format_etc_gmt(i64::MAX), "292278994-08-17 07:12:55 Etc/GMT");
}

/// The Pacific rendering at a sample of 1900-2100 (one instant every 7,919
/// seconds, so every hour and minute of the day comes round), at every
/// transition and the second before it, and at a sparser sample out to the
/// year 10000. The full minute-by-minute run is the ignored test below.
#[test]
fn the_pacific_rendering_matches_the_hand_written_rules_at_a_sample() {
    let mut checked = 0u64;
    let mut check = |seconds: i64| {
        let millis = seconds * 1000;
        assert_eq!(
            format_pacific(millis),
            old::format_pacific(millis),
            "at {millis}"
        );
        checked += 1;
    };
    let mut s = FROM_1900;
    while s < TO_2100 {
        check(s);
        s += 7_919;
    }
    for at in transitions() {
        check(at - 1);
        check(at);
    }
    let mut s = TO_2100;
    while s < 253_402_300_800 {
        check(s);
        s += 1_000_003;
    }
    assert!(checked > 1_000_000, "{checked}");
}

/// The receipt-date grammar, old against new: every month 00-13 and day
/// 00-32 of years at the edges of the leap rules, hours, minutes and
/// seconds either side of their limits, every printable byte at every
/// position of one valid date, and the lengths either side of 20.
#[test]
fn the_receipt_date_grammar_is_unchanged() {
    let mut checked = 0u64;
    let mut check = |text: &str| {
        assert_eq!(
            parse_receipt_date(text),
            old::parse_receipt_date(text),
            "{text:?}"
        );
        checked += 1;
    };
    for year in [0, 1, 4, 100, 400, 1900, 1970, 2000, 2023, 2024, 2100, 9999] {
        for month in 0..=13 {
            for day in 0..=32 {
                for hour in [0, 23, 24, 99] {
                    for minute in [0, 59, 60] {
                        for second in [0, 59, 60] {
                            check(&format!(
                                "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
                            ));
                        }
                    }
                }
            }
        }
    }
    let valid = "2024-02-29T23:59:59Z";
    for at in 0..valid.len() {
        for byte in 0x20u8..0x7f {
            let mut text = valid.as_bytes().to_vec();
            text[at] = byte;
            check(std::str::from_utf8(&text).unwrap());
        }
    }
    check("2024-02-29T23:59:59");
    check("2024-02-29T23:59:59ZZ");
    check("2024-02-29T23:59:5Z");
    assert!(checked > 100_000, "{checked}");
}

/// The spike's differential (docs/evidence/2026-10-01-pacific-tz-crates),
/// ported: the US-Pacific offset at every minute from 1900-01-01 to
/// 2100-01-01 and at every transition and the second before it, every
/// hour from 2100 to 2900 (across the 400-year fold at 2500), the GMT
/// rendering at every hour of one whole 400-year cycle (1970-2370), and
/// both renderings at 2^20 instants strided across the whole `i64` range.
/// About 117 million comparisons; run with
/// `cargo test --release --test datetime -- --ignored`.
#[test]
#[ignore = "about 117 million comparisons: seconds in a release build, minutes in a debug one"]
fn the_pacific_offset_matches_the_hand_written_rules_at_every_minute_1900_to_2100() {
    let mut checked = 0u64;
    let mut offset = |seconds: i64| {
        let millis = seconds * 1000;
        assert_eq!(
            pacific_offset_seconds(millis),
            old::pacific_offset_seconds(millis),
            "at {millis}"
        );
        checked += 1;
    };
    let mut s = FROM_1900;
    while s < TO_2100 {
        offset(s);
        s += 60;
    }
    for at in transitions() {
        offset(at - 1);
        offset(at);
    }
    let mut s = TO_2100;
    while s < 29_348_006_400 {
        // 2900-01-01T00:00:00Z
        offset(s);
        s += 3_600;
    }
    let mut s = 0;
    while s < 146_097 * 86_400 {
        let millis = s * 1000;
        assert_eq!(
            format_etc_gmt(millis),
            old::format_etc_gmt(millis),
            "at {millis}"
        );
        checked += 1;
        s += 3_600;
    }
    let stride = (u64::MAX >> 20) as i64;
    let mut millis = i64::MIN;
    for _ in 0..(1u32 << 20) {
        assert_eq!(
            format_etc_gmt(millis),
            old::format_etc_gmt(millis),
            "at {millis}"
        );
        assert_eq!(
            format_pacific(millis),
            old::format_pacific(millis),
            "at {millis}"
        );
        checked += 1;
        millis = millis.wrapping_add(stride);
    }
    println!("{checked} comparisons, 0 disagreements");
}
