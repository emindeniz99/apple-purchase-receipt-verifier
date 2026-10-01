#[path = "../../../common/pacific.rs"]
mod pacific;

use chrono::{DateTime, Offset, TimeZone};
fn offset(millis: i64) -> i64 {
    match DateTime::from_timestamp_millis(millis) {
        Some(dt) => i64::from(chrono_tz::America::Los_Angeles.offset_from_utc_datetime(&dt.naive_utc()).fix().local_minus_utc()),
        None => -8 * 3600,
    }
}

fn main() {
    let millis: i64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    println!("{}", pacific::format_civil(millis, offset(millis), "America/Los_Angeles"));
}
