#[path = "../../../common/pacific.rs"]
mod pacific;

fn offset(_millis: i64) -> i64 { -8 * 3600 }

fn main() {
    let millis: i64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    println!("{}", pacific::format_civil(millis, offset(millis), "America/Los_Angeles"));
}
