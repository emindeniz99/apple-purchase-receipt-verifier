#[path = "../../../common/pacific.rs"]
mod pacific;

fn offset(millis: i64) -> i64 {
    tzdb_data::time_zone::america::LOS_ANGELES.find_local_time_type(millis.div_euclid(1000)).map(|t| i64::from(t.ut_offset())).unwrap_or(-8 * 3600)
}

fn main() {
    let millis: i64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    println!("{}", pacific::format_civil(millis, offset(millis), "America/Los_Angeles"));
}
