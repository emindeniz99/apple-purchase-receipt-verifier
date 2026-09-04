//! Calendar arithmetic: the RFC 3339 grammar a receipt attribute must obey,
//! and the two renderings Apple's `verifyReceipt` response uses.
//!
//! The US-Pacific vectors below were generated from Python's `zoneinfo`
//! (the IANA database) rather than from this implementation, so they are not
//! self-referential. They cover both transitions in both directions under
//! both the pre-2007 and the current US rules.

use apple_purchase_receipt_verifier::datetime::{
    format_etc_gmt, format_pacific, pacific_offset_seconds, parse_rfc3339, system_time_from_millis,
    to_rfc3339_utc, unix_millis_of,
};

/// `(epoch millis, expected US-Pacific rendering)`, from IANA via
/// `zoneinfo`. Where this port and Ruby both hand-roll the rule, these are
/// the vectors both should be reading.
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
fn iso_8601_drops_a_zero_millisecond_component() {
    assert_eq!(
        to_rfc3339_utc(system_time_from_millis(1_722_945_600_000)),
        "2024-08-06T12:00:00Z"
    );
    assert_eq!(
        to_rfc3339_utc(system_time_from_millis(1_722_945_600_250)),
        "2024-08-06T12:00:00.250Z"
    );
    assert_eq!(
        to_rfc3339_utc(system_time_from_millis(0)),
        "1970-01-01T00:00:00Z"
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
        assert_eq!(
            unix_millis_of(system_time_from_millis(millis)),
            millis,
            "at {millis}"
        );
    }
}

#[test]
fn rfc_3339_requires_a_timezone_designator() {
    assert!(parse_rfc3339("2024-08-06T12:00:00").is_none());
    assert!(parse_rfc3339("2024-08-06T12:00:00 ").is_none());
    assert!(
        parse_rfc3339("2024-08-06T12:00:00z").is_none(),
        "the designator is case-sensitive"
    );
}

#[test]
fn rfc_3339_accepts_the_forms_receipts_actually_carry() {
    assert_eq!(
        parse_rfc3339("2024-08-06T12:00:00Z"),
        Some(1_722_945_600_000)
    );
    assert_eq!(
        parse_rfc3339("2024-08-06T12:00:00.000Z"),
        Some(1_722_945_600_000)
    );
    assert_eq!(
        parse_rfc3339("2024-08-06T12:00:00.25Z"),
        Some(1_722_945_600_250)
    );
    assert_eq!(
        parse_rfc3339("2024-08-06T12:00:00.250000Z"),
        Some(1_722_945_600_250)
    );
    assert_eq!(
        parse_rfc3339("2024-08-06T05:00:00-07:00"),
        Some(1_722_945_600_000)
    );
    assert_eq!(
        parse_rfc3339("2024-08-06T19:00:00+07:00"),
        Some(1_722_945_600_000)
    );
}

#[test]
fn rfc_3339_rejects_impossible_dates() {
    for text in [
        "2024-02-30T00:00:00Z",
        "2023-02-29T00:00:00Z",
        "2024-13-01T00:00:00Z",
        "2024-00-01T00:00:00Z",
        "2024-01-00T00:00:00Z",
        "2024-01-32T00:00:00Z",
        "2024-01-01T24:00:00Z",
        "2024-01-01T00:60:00Z",
        "2024-01-01T00:00:60Z",
    ] {
        assert!(parse_rfc3339(text).is_none(), "{text} must be refused");
    }
    // But a real leap day is fine.
    assert!(parse_rfc3339("2024-02-29T00:00:00Z").is_some());
    assert!(parse_rfc3339("2000-02-29T00:00:00Z").is_some());
    assert!(
        parse_rfc3339("1900-02-29T00:00:00Z").is_none(),
        "1900 was not a leap year"
    );
}

#[test]
fn rfc_3339_rejects_malformed_shapes() {
    for text in [
        "",
        "2024",
        "2024-08-06",
        "20240806T120000Z",
        "2024/08/06T12:00:00Z",
        "2024-08-06 12:00:00Z",
        "2024-08-06T12:00:00.Z",
        "2024-08-06T12:00:00+7:00",
        "2024-08-06T12:00:00+0700",
        "2024-08-06T12:00:00Zextra",
        "2024-08-06T12:00:00+25:00",
        "20x4-08-06T12:00:00Z",
    ] {
        assert!(parse_rfc3339(text).is_none(), "{text:?} must be refused");
    }
}

#[test]
fn parse_and_render_round_trip_across_a_century() {
    // Every first-of-month from 1970 to 2070: the civil-date arithmetic has
    // no calendar it can quietly get wrong.
    for year in 1970..2070 {
        for month in 1..=12 {
            let text = format!("{year:04}-{month:02}-01T00:00:00Z");
            let millis = parse_rfc3339(&text).unwrap_or_else(|| panic!("{text}"));
            assert_eq!(to_rfc3339_utc(system_time_from_millis(millis)), text);
        }
    }
}

#[test]
fn every_day_of_2024_round_trips() {
    let mut millis = parse_rfc3339("2024-01-01T00:00:00Z").unwrap();
    let end = parse_rfc3339("2025-01-01T00:00:00Z").unwrap();
    let mut days = 0;
    while millis < end {
        let text = to_rfc3339_utc(system_time_from_millis(millis));
        assert_eq!(parse_rfc3339(&text), Some(millis), "{text}");
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
/// the test that keeps a dependency-free rule set honest against them.
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
    let at = parse_rfc3339("1970-04-26T10:00:00Z").unwrap();
    assert_eq!(
        format_pacific(at),
        "1970-04-26 03:00:00 America/Los_Angeles"
    );
    assert_eq!(
        format_pacific(at - 1000),
        "1970-04-26 01:59:59 America/Los_Angeles"
    );
    // The Emergency Daylight Saving Time Act years are not the usual rule.
    let jan_1974 = parse_rfc3339("1974-01-06T10:00:00Z").unwrap();
    assert_eq!(pacific_offset_seconds(jan_1974), -7 * 3600);
    assert_eq!(pacific_offset_seconds(jan_1974 - 1000), -8 * 3600);
    let feb_1975 = parse_rfc3339("1975-02-23T10:00:00Z").unwrap();
    assert_eq!(pacific_offset_seconds(feb_1975), -7 * 3600);
    assert_eq!(pacific_offset_seconds(feb_1975 - 1000), -8 * 3600);
    // Wartime daylight time ran continuously for three and a half years.
    let wartime = parse_rfc3339("1943-07-01T12:00:00Z").unwrap();
    assert_eq!(pacific_offset_seconds(wartime), -7 * 3600);
    // 1950-1966 switched at 01:00 local, not 02:00.
    let y1950 = parse_rfc3339("1950-04-30T09:00:00Z").unwrap();
    assert_eq!(pacific_offset_seconds(y1950), -7 * 3600);
    assert_eq!(pacific_offset_seconds(y1950 - 1000), -8 * 3600);
}
