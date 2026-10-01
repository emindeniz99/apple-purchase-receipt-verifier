//! Compares each candidate's US-Pacific UTC offset with the repo's
//! hand-written `pacific_offset_seconds`, at every minute from
//! 1900-01-01T00:00Z to 2100-01-01T00:00Z, and at the second before and the
//! second of every transition in rust/tests/data/pacific-transitions.txt
//! and in the system TZif file. Disagreements are reported as ranges.
#[path = "../../common/pacific.rs"]
mod pacific;

use chrono::{DateTime, Offset, TimeZone as _};
use time_tz::{Offset as _, TimeZone as _};

static TZIF: &[u8] = include_bytes!("../../data/America_Los_Angeles.tzif");
static JIFF_STATIC: jiff::tz::TimeZone = jiff::tz::get!("America/Los_Angeles");

const START: i64 = -2_208_988_800; // 1900-01-01T00:00:00Z
const END: i64 = 4_102_444_800; // 2100-01-01T00:00:00Z

fn main() {
    let jiff_posix = jiff::tz::TimeZone::posix("PST8PDT,M3.2.0,M11.1.0").unwrap();
    let jiff_tzif = jiff::tz::TimeZone::tzif("America/Los_Angeles", TZIF).unwrap();
    let tzrs = tz::TimeZone::from_tz_data(TZIF).unwrap();
    // Extra probe points: each known transition, the second before and of it.
    let mut probes: Vec<i64> = Vec::new();
    let file = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../rust/tests/data/pacific-transitions.txt")).unwrap();
    for line in file.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
        let t: i64 = line.split_whitespace().next().unwrap().parse().unwrap();
        probes.extend([t - 1, t]);
    }
    for t in tzrs.as_ref().transitions().iter().map(|t| t.unix_leap_time()) {
        if (START..END).contains(&t) {
            probes.extend([t - 1, t]);
        }
    }
    let jiff_off = |tz: &jiff::tz::TimeZone, s: i64| {
        i64::from(tz.to_offset(jiff::Timestamp::from_second(s).unwrap()).seconds())
    };
    let candidates: Vec<(&str, Box<dyn Fn(i64) -> i64>)> = vec![
        ("chrono-tz 0.10.4 (filtered)", Box::new(|s| {
            let dt = DateTime::from_timestamp(s, 0).unwrap().naive_utc();
            i64::from(chrono_tz::America::Los_Angeles.offset_from_utc_datetime(&dt).fix().local_minus_utc())
        })),
        ("jiff posix PST8PDT,M3.2.0,M11.1.0", Box::new(move |s| jiff_off(&jiff_posix, s))),
        ("jiff tz::get! (jiff-tzdb)", Box::new(move |s| jiff_off(&JIFF_STATIC, s))),
        ("jiff TimeZone::tzif (system TZif)", Box::new(move |s| jiff_off(&jiff_tzif, s))),
        ("tz-rs from_tz_data (system TZif)", Box::new(move |s| {
            i64::from(tzrs.find_local_time_type(s).unwrap().ut_offset())
        })),
        ("tzdb_data 0.2.5 LOS_ANGELES", Box::new(|s| {
            i64::from(tzdb_data::time_zone::america::LOS_ANGELES.find_local_time_type(s).unwrap().ut_offset())
        })),
        ("time-tz 2.0.0", Box::new(|s| {
            let odt = time::OffsetDateTime::from_unix_timestamp(s).unwrap();
            i64::from(time_tz::timezones::db::america::LOS_ANGELES.get_offset_utc(&odt).to_utc().whole_seconds())
        })),
    ];

    println!("probe points from transition lists: {}", probes.len());

    for (name, f) in &candidates {
        let mut ranges: Vec<(i64, i64, i64, i64)> = Vec::new(); // start, last, hand, cand
        let mut count: u64 = 0;
        let check = |s: i64, ranges: &mut Vec<(i64, i64, i64, i64)>, count: &mut u64| {
            let hand = pacific::pacific_offset_seconds(s * 1000);
            let cand = f(s);
            if hand != cand {
                *count += 1;
                match ranges.last_mut() {
                    Some(r) if r.2 == hand && r.3 == cand && s - r.1 <= 60 && s > r.1 => r.1 = s,
                    _ => ranges.push((s, s, hand, cand)),
                }
            }
        };
        let mut s = START;
        while s < END {
            check(s, &mut ranges, &mut count);
            s += 60;
        }
        let minute_count = count;
        for &p in &probes {
            check(p, &mut ranges, &mut count);
        }
        println!(
            "\n{name}: {minute_count} disagreeing minutes, {} disagreeing transition probes, {} ranges",
            count - minute_count,
            ranges.len()
        );
        for r in ranges.iter().take(6) {
            println!(
                "  {} .. {}  hand {}  candidate {}",
                pacific::format_civil(r.0 * 1000, 0, "UTC"),
                pacific::format_civil(r.1 * 1000, 0, "UTC"),
                r.2,
                r.3
            );
        }
        if ranges.len() > 6 {
            let r = ranges.last().unwrap();
            println!("  ... last: {} .. {}", pacific::format_civil(r.0 * 1000, 0, "UTC"), pacific::format_civil(r.1 * 1000, 0, "UTC"));
        }
    }
}
