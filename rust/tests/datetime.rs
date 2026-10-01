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
    renders, unix_millis_of,
};
use hand_written_datetime as old;
use std::time::{Duration, UNIX_EPOCH};

/// The renderings and the offset of an instant every test below expects to
/// render.
fn pacific(millis: i64) -> String {
    format_pacific(millis).unwrap_or_else(|| panic!("{millis} renders"))
}

fn gmt(millis: i64) -> String {
    format_etc_gmt(millis).unwrap_or_else(|| panic!("{millis} renders"))
}

fn offset(millis: i64) -> i64 {
    pacific_offset_seconds(millis).unwrap_or_else(|| panic!("{millis} renders"))
}

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
        assert_eq!(pacific(millis), expected, "at {millis}");
    }
}

#[test]
fn the_pacific_offset_is_minus_seven_or_minus_eight() {
    for (millis, expected) in PACIFIC_VECTORS {
        let offset = offset(millis);
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
    assert_eq!(offset(1_710_064_799_999), -8 * 3600);
    assert_eq!(offset(1_710_064_800_000), -7 * 3600);
    // And of the autumn fall-back instant.
    assert_eq!(offset(1_730_624_399_999), -7 * 3600);
    assert_eq!(offset(1_730_624_400_000), -8 * 3600);
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
    assert_eq!(offset(331_214_400_000), -7 * 3600);
}

#[test]
fn the_gmt_rendering_is_apples_etc_gmt_form() {
    assert_eq!(gmt(1_722_945_600_000), "2024-08-06 12:00:00 Etc/GMT");
    assert_eq!(gmt(0), "1970-01-01 00:00:00 Etc/GMT");
    assert_eq!(gmt(1_735_689_600_000), "2025-01-01 00:00:00 Etc/GMT");
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
                gmt(millis),
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
        let gmt = gmt(millis);
        let text = format!("{}Z", gmt.trim_end_matches(" Etc/GMT").replace(' ', "T"));
        assert_eq!(parse_receipt_date(&text), Some(millis), "{text}");
        // And the Pacific rendering never produces an impossible clock face.
        let pacific = pacific(millis);
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
            offset((at - 1) * 1000),
            before,
            "one second before the transition at {at}"
        );
        assert_eq!(offset(at * 1000), after, "at the transition at {at}");
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
    assert_eq!(pacific(at), "1970-04-26 03:00:00 America/Los_Angeles");
    assert_eq!(
        pacific(at - 1000),
        "1970-04-26 01:59:59 America/Los_Angeles"
    );
    // The Emergency Daylight Saving Time Act years are not the usual rule.
    let jan_1974 = parse_receipt_date("1974-01-06T10:00:00Z").unwrap();
    assert_eq!(offset(jan_1974), -7 * 3600);
    assert_eq!(offset(jan_1974 - 1000), -8 * 3600);
    let feb_1975 = parse_receipt_date("1975-02-23T10:00:00Z").unwrap();
    assert_eq!(offset(feb_1975), -7 * 3600);
    assert_eq!(offset(feb_1975 - 1000), -8 * 3600);
    // Wartime daylight time ran continuously for three and a half years.
    let wartime = parse_receipt_date("1943-07-01T12:00:00Z").unwrap();
    assert_eq!(offset(wartime), -7 * 3600);
    // 1950-1966 switched at 01:00 local, not 02:00.
    let y1950 = parse_receipt_date("1950-04-30T09:00:00Z").unwrap();
    assert_eq!(offset(y1950), -7 * 3600);
    assert_eq!(offset(y1950 - 1000), -8 * 3600);
}

// --- the jiff-based code against the hand-written code it replaced ------
//
// The two agree from 1883-11-18T20:00:00Z, where the IANA database starts
// Pacific standard time, to the receipt grammar's last second. Before it
// the database (and so jiff, and Java's ZoneId) gives local mean time,
// −07:52:58, where the hand-written code answered PST.

/// 1883-11-18T20:00:00Z, 2100-01-01T00:00:00Z, and the receipt grammar's
/// last second, 9999-12-31T23:59:59Z.
const FROM_1883: i64 = -2_717_640_000;
const TO_2100: i64 = 4_102_444_800;
const LAST_SECOND: i64 = 253_402_300_799;
/// jiff's last instant, 9999-12-30T22:00:00.999999999Z, in milliseconds.
const JIFF_LAST_MILLIS: i64 = 253_402_207_200_999;
/// −07:52:58, Los Angeles local mean time.
const LMT: i64 = -(7 * 3600 + 52 * 60 + 58);

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

/// The new renderings and offset at `millis` against the hand-written ones.
fn assert_same(millis: i64) {
    assert_eq!(
        format_etc_gmt(millis),
        Some(old::format_etc_gmt(millis)),
        "GMT at {millis}"
    );
    assert_eq!(
        format_pacific(millis),
        Some(old::format_pacific(millis)),
        "Pacific at {millis}"
    );
    assert_eq!(
        pacific_offset_seconds(millis),
        Some(old::pacific_offset_seconds(millis)),
        "offset at {millis}"
    );
}

/// Instants whose renderings must not change by a byte: both transitions of
/// 1950, 1998, 2007 and 2026 (the second before, the last millisecond
/// before, the second of and the one after each), the epoch, the 1883 and
/// 1900 edges, and the last 26 hours of the year 9999, which lie past
/// jiff's last instant.
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
        FROM_1883 * 1000,
        FROM_1883 * 1000 + 1,
        -2_208_988_800_000, // 1900-01-01T00:00:00Z
        -2_208_988_800_001,
        253_402_207_200_000, // 9999-12-30T22:00:00Z
        253_402_207_200_001, // 9999-12-30T22:00:00.001Z
        JIFF_LAST_MILLIS,
        JIFF_LAST_MILLIS + 1, // the first millisecond past jiff
        253_402_214_400_000,  // 9999-12-31T00:00:00Z
        LAST_SECOND * 1000,   // 9999-12-31T23:59:59Z
        LAST_SECOND * 1000 + 999,
    ]);
    for millis in instants {
        assert_same(millis);
        for offset in [-12 * 3600, 0] {
            assert_eq!(
                format_civil(millis, offset, "X"),
                Some(old::format_civil(millis, offset, "X")),
                "civil at {millis} offset {offset}"
            );
        }
    }
}

/// The year 9999 past jiff's last instant, both renderings, written out.
#[test]
fn the_last_26_hours_of_9999_render() {
    for (millis, utc, pacific_time) in [
        (
            253_402_207_200_001,
            "9999-12-30 22:00:00 Etc/GMT",
            "9999-12-30 14:00:00 America/Los_Angeles",
        ),
        (
            253_402_214_400_000,
            "9999-12-31 00:00:00 Etc/GMT",
            "9999-12-30 16:00:00 America/Los_Angeles",
        ),
        (
            LAST_SECOND * 1000,
            "9999-12-31 23:59:59 Etc/GMT",
            "9999-12-31 15:59:59 America/Los_Angeles",
        ),
    ] {
        assert_eq!(format_etc_gmt(millis).as_deref(), Some(utc), "at {millis}");
        assert_eq!(
            format_pacific(millis).as_deref(),
            Some(pacific_time),
            "at {millis}"
        );
    }
    assert_eq!(
        parse_receipt_date("9999-12-31T23:59:59Z"),
        Some(LAST_SECOND * 1000)
    );
}

/// Past jiff's last instant the offset is the one at that instant. That is
/// exact only because the zone's rule puts all of 9999-12-30 and -31 in
/// standard time: nothing changes from the first Sunday in November 9999
/// until March 10000.
#[test]
fn the_end_of_9999_is_standard_time() {
    let mut s = 253_399_708_800; // 9999-12-01T00:00:00Z
    while s * 1000 <= JIFF_LAST_MILLIS {
        assert_eq!(pacific_offset_seconds(s * 1000), Some(-8 * 3600), "at {s}");
        s += 3_600;
    }
    for millis in [JIFF_LAST_MILLIS + 1, LAST_SECOND * 1000 + 999] {
        assert_eq!(
            pacific_offset_seconds(millis),
            Some(-8 * 3600),
            "at {millis}"
        );
    }
}

/// Before 1883-11-18T20:00:00Z the database's answer is local mean time,
/// −07:52:58, and it is taken as it is: the year 0000 of a receipt date
/// renders in Pacific time as 2 BC, which jiff prints `-001`.
#[test]
fn before_1883_the_offset_is_local_mean_time() {
    assert_eq!(pacific_offset_seconds(FROM_1883 * 1000 - 1), Some(LMT));
    assert_eq!(pacific_offset_seconds(FROM_1883 * 1000), Some(-8 * 3600));
    assert_eq!(
        format_pacific(FROM_1883 * 1000 - 1000).as_deref(),
        Some("1883-11-18 12:07:01 America/Los_Angeles")
    );
    let year_0 = parse_receipt_date("0000-01-01T00:00:00Z").unwrap();
    assert_eq!(pacific_offset_seconds(year_0), Some(LMT));
    assert_eq!(
        format_etc_gmt(year_0).as_deref(),
        Some("0000-01-01 00:00:00 Etc/GMT")
    );
    assert_eq!(
        format_pacific(year_0).as_deref(),
        Some("-001-12-31 16:07:02 America/Los_Angeles")
    );
    // Years 0 to 999 keep four digits, as before.
    let year_999 = parse_receipt_date("0999-06-15T12:00:00Z").unwrap();
    assert_eq!(
        format_etc_gmt(year_999).as_deref(),
        Some("0999-06-15 12:00:00 Etc/GMT")
    );
    assert_eq!(
        format_etc_gmt(year_999),
        Some(old::format_etc_gmt(year_999))
    );
}

/// Outside jiff's first instant and the grammar's last second nothing
/// renders; the endpoint answers such a clock as broken (tests/endpoint.rs).
#[test]
fn instants_outside_the_range_do_not_render() {
    let first = -377_705_023_201_000; // -9999-01-02T01:59:59Z, jiff's first
    assert!(renders(first));
    assert!(format_pacific(first).is_some() && format_etc_gmt(first).is_some());
    assert!(renders(LAST_SECOND * 1000 + 999));
    for millis in [first - 1, LAST_SECOND * 1000 + 1000, i64::MAX, i64::MIN] {
        assert!(!renders(millis), "{millis}");
        assert_eq!(format_etc_gmt(millis), None, "{millis}");
        assert_eq!(format_pacific(millis), None, "{millis}");
        assert_eq!(pacific_offset_seconds(millis), None, "{millis}");
    }
    assert_eq!(format_civil(i64::MAX, 1, "X"), None);
}

/// The Pacific rendering at a sample of 1883-2100 (one instant every 7,919
/// seconds, so every hour and minute of the day comes round), at every
/// transition and the second before it, and at a sparser sample to the end
/// of 9999. The full run is the ignored test below.
#[test]
fn the_pacific_rendering_matches_the_hand_written_rules_at_a_sample() {
    let mut checked = 0u64;
    let mut check = |seconds: i64| {
        let millis = seconds * 1000;
        assert_eq!(
            format_pacific(millis),
            Some(old::format_pacific(millis)),
            "at {millis}"
        );
        checked += 1;
    };
    let mut s = FROM_1883;
    while s < TO_2100 {
        check(s);
        s += 7_919;
    }
    for at in transitions() {
        check(at - 1);
        check(at);
    }
    let mut s = TO_2100;
    while s <= LAST_SECOND {
        check(s);
        s += 1_000_003;
    }
    check(LAST_SECOND);
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
/// ported and widened to every instant both codes render alike: the
/// US-Pacific offset at every minute from 1883-11-18T20:00:00Z to
/// 2100-01-01 and at every transition and the second before it, and both
/// renderings at every hour from 2100 to the grammar's last second. Run with
/// `cargo test --release --test datetime -- --ignored`.
#[test]
#[ignore = "about 183 million instants: under two minutes in a release build, far longer in a debug one"]
fn the_pacific_offset_matches_the_hand_written_rules_from_1883_to_9999() {
    let mut checked = 0u64;
    let mut s = FROM_1883;
    while s < TO_2100 {
        let millis = s * 1000;
        assert_eq!(
            pacific_offset_seconds(millis),
            Some(old::pacific_offset_seconds(millis)),
            "at {millis}"
        );
        checked += 1;
        s += 60;
    }
    for at in transitions() {
        assert_same((at - 1) * 1000);
        assert_same(at * 1000);
        checked += 2;
    }
    let mut s = TO_2100;
    while s <= LAST_SECOND {
        let millis = s * 1000;
        assert_eq!(
            format_etc_gmt(millis),
            Some(old::format_etc_gmt(millis)),
            "at {millis}"
        );
        assert_eq!(
            format_pacific(millis),
            Some(old::format_pacific(millis)),
            "at {millis}"
        );
        checked += 1;
        s += 3_600;
    }
    assert_same(LAST_SECOND * 1000);
    checked += 1;
    println!("{checked} instants compared, 0 disagreements");
}

/// `format_civil` prints jiff's civil fields itself, since `strftime` adds
/// 237 KB to the module; this holds the two to the same bytes over the whole
/// year range, negative years included.
#[test]
fn the_rendering_is_jiffs_own_strftime() {
    let mut s = -377_705_023_201; // jiff's first second
    while s <= LAST_SECOND {
        let millis = s * 1000;
        let at = jiff::Timestamp::from_second(s.min(jiff::Timestamp::MAX.as_second())).unwrap();
        let extra = i32::try_from(s - at.as_second()).unwrap();
        let civil = jiff::tz::Offset::from_seconds(extra)
            .unwrap()
            .to_datetime(at);
        assert_eq!(
            format_civil(millis, 0, "X"),
            Some(format!("{} X", civil.strftime("%Y-%m-%d %H:%M:%S"))),
            "at {s}"
        );
        s += 86_400 * 37 + 3_607;
    }
}
