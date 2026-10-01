#[path = "../../../common/pacific.rs"]
mod pacific;

fn offset(millis: i64) -> i64 { pacific::pacific_offset_seconds(millis) }

fn main() {
    let millis: i64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    println!("{}", pacific::format_civil(millis, offset(millis), "America/Los_Angeles"));
}
