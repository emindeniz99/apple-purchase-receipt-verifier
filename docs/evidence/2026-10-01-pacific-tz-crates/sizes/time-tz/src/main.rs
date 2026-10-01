#[path = "../../../common/pacific.rs"]
mod pacific;

use time_tz::{Offset, TimeZone};
fn offset(millis: i64) -> i64 {
    match time::OffsetDateTime::from_unix_timestamp(millis.div_euclid(1000)) {
        Ok(odt) => i64::from(time_tz::timezones::db::america::LOS_ANGELES.get_offset_utc(&odt).to_utc().whole_seconds()),
        Err(_) => -8 * 3600,
    }
}

fn main() {
    let millis: i64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    println!("{}", pacific::format_civil(millis, offset(millis), "America/Los_Angeles"));
}
