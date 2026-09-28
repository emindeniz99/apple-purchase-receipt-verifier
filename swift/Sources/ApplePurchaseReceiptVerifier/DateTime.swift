import Foundation

/// Epoch milliseconds as a `Date`. Always representable: an `Int64` cast to
/// `Double` is always finite, so this never produces a NaN or infinite date.
func dateFromMillis(_ millis: Int64) -> Date {
    Date(timeIntervalSince1970: Double(millis) / 1000.0)
}

/// A receipt date attribute parses only in the exact form
/// `YYYY-MM-DDTHH:MM:SSZ`: a four-digit year 0000 to 9999, uppercase `T` and
/// `Z`, a real calendar date (leap years included), hours 00 to 23, minutes
/// and seconds 00 to 59, no fraction and no offset. Anything else is `nil`.
/// A hand-written grammar rather than a general-purpose parser, because the
/// input is unverified when the chain instant is read from it, and a general
/// parser (locale-, platform- or offset-aware) accepts strings this format
/// does not.
func parseReceiptDate(_ text: String) -> Int64? {
    let bytes = Array(text.utf8)
    guard bytes.count == 20 else { return nil }
    func digit(_ index: Int) -> Int? {
        let byte = bytes[index]
        guard byte >= 0x30, byte <= 0x39 else { return nil }
        return Int(byte - 0x30)
    }
    func twoDigits(_ index: Int) -> Int? {
        guard let tens = digit(index), let ones = digit(index + 1) else { return nil }
        return tens * 10 + ones
    }
    guard let y0 = digit(0), let y1 = digit(1), let y2 = digit(2), let y3 = digit(3) else { return nil }
    let year = y0 * 1000 + y1 * 100 + y2 * 10 + y3
    guard bytes[4] == 0x2D else { return nil }  // '-'
    guard let month = twoDigits(5) else { return nil }
    guard bytes[7] == 0x2D else { return nil }
    guard let day = twoDigits(8) else { return nil }
    guard bytes[10] == 0x54 else { return nil }  // 'T'
    guard let hour = twoDigits(11) else { return nil }
    guard bytes[13] == 0x3A else { return nil }  // ':'
    guard let minute = twoDigits(14) else { return nil }
    guard bytes[16] == 0x3A else { return nil }
    guard let second = twoDigits(17) else { return nil }
    guard bytes[19] == 0x5A else { return nil }  // 'Z'
    guard (1...12).contains(month) else { return nil }
    guard let daysInMonth = daysInMonth(year: year, month: month), (1...daysInMonth).contains(day) else {
        return nil
    }
    guard (0...23).contains(hour), (0...59).contains(minute), (0...59).contains(second) else {
        return nil
    }
    guard let days = daysSinceEpoch(year: year, month: month, day: day) else { return nil }
    let seconds = Int64(days) * 86400 + Int64(hour) * 3600 + Int64(minute) * 60 + Int64(second)
    return seconds * 1000
}

private func isLeapYear(_ year: Int) -> Bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

private func daysInMonth(year: Int, month: Int) -> Int? {
    switch month {
    case 1, 3, 5, 7, 8, 10, 12: return 31
    case 4, 6, 9, 11: return 30
    case 2: return isLeapYear(year) ? 29 : 28
    default: return nil
    }
}

/// Days from 1970-01-01 to `year-month-day` (proleptic Gregorian), which may
/// be negative for a year before 1970. Used only after every field has
/// already been range-checked. Howard Hinnant's `days_from_civil`
/// (<https://howardhinnant.github.io/date_algorithms.html>), a well-tested
/// closed-form correct for the whole proleptic Gregorian calendar, including
/// year 0000 and negative years — deliberately not derived from `Foundation`
/// or `Calendar`, which read unverified receipt bytes before any signature
/// has verified.
private func daysSinceEpoch(year: Int, month: Int, day: Int) -> Int? {
    let y = month <= 2 ? year - 1 : year
    let era = (y >= 0 ? y : y - 399) / 400
    let yoe = y - era * 400
    let doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
    return era * 146097 + doe - 719468
}

// MARK: - Apple's endpoint date renderings
//
// `yyyy-MM-dd HH:mm:ss` plus a literal zone name, carried over from 0.6:
// `America/Los_Angeles` is the real IANA zone (it observes daylight saving),
// so this reuses Foundation's `Date.VerbatimFormatStyle` and a real
// `TimeZone`, rather than a fixed UTC offset — a fixed offset would be wrong
// for half the year.

/// Value types and `Sendable`, so each is built once and serves every
/// thread; Foundation caches the formatter behind them. A new
/// `DateFormatter` per date cost about 95 µs on Linux in 0.6's measurement,
/// and swift-corelibs-foundation's `DateFormatter` has no lock, so one cannot
/// be shared between threads.
private let appleGMTDateStyle = appleDateStyle(TimeZone(identifier: "UTC")!)
private let applePacificDateStyle = appleDateStyle(TimeZone(identifier: "America/Los_Angeles")!)

private func appleDateStyle(_ zone: TimeZone) -> Date.VerbatimFormatStyle {
    var calendar = Calendar(identifier: .gregorian)
    calendar.timeZone = zone
    return Date.VerbatimFormatStyle(
        format: """
            \(year: .padded(4))-\(month: .twoDigits)-\(day: .twoDigits) \
            \(hour: .twoDigits(clock: .twentyFourHour, hourCycle: .zeroBased)):\
            \(minute: .twoDigits):\(second: .twoDigits)
            """,
        locale: Locale(identifier: "en_US_POSIX"), timeZone: zone, calendar: calendar)
}

/// `receipt_creation_date` and friends, GMT: `Etc/GMT`, Apple's literal zone
/// name for the non-suffixed key.
func formatEtcGMT(millis: Int64) -> String {
    dateFromMillis(millis).formatted(appleGMTDateStyle) + " Etc/GMT"
}

/// `receipt_creation_date_pst` and friends: US Pacific time, Apple's literal
/// `America/Los_Angeles` zone name.
func formatPacific(millis: Int64) -> String {
    dateFromMillis(millis).formatted(applePacificDateStyle) + " America/Los_Angeles"
}
