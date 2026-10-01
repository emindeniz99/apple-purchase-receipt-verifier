#[path = "../../../common/pacific.rs"]
mod pacific;

static TZIF: &[u8] = include_bytes!("../../../data/America_Los_Angeles.tzif");
fn offset(millis: i64) -> i64 {
    let tz = jiff::tz::TimeZone::tzif("America/Los_Angeles", TZIF).unwrap();
    match jiff::Timestamp::from_millisecond(millis) {
        Ok(ts) => i64::from(tz.to_offset(ts).seconds()),
        Err(_) => -8 * 3600,
    }
}

fn main() {
    let millis: i64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    println!("{}", pacific::format_civil(millis, offset(millis), "America/Los_Angeles"));
}
