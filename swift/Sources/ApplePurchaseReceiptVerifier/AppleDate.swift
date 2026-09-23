import Foundation

// Receipt dates, parsed and rendered without a Foundation formatter on the
// common path.
//
// Every receipt date used to build its own `ISO8601DateFormatter` (and
// try it twice, fractional seconds first), and every rendered date built two
// `DateFormatter`s. On Linux each of those costs tens to hundreds of
// microseconds, and a receipt with 187 purchases carries 563 dates: measured
// on a release build (Swift 6.3.3, Linux x86_64), parsing them took about
// 170 ms and rendering them about 108 ms, nearly all of `verifyCore` and of
// the endpoint's answer. Sharing one formatter is no fix: a shared
// `ISO8601DateFormatter` still took about 32 ms for the same dates, and it
// is not safe to share across threads in swift-corelibs-foundation.
//
// So the shapes genuine receipts use are handled here by arithmetic, and
// everything else goes to Foundation exactly as before, so no answer moves.
// AppleDateTests compares both halves against Foundation over generated and
// hand-picked inputs, DST transitions included.

private let secondsPerDay = 86_400

/// Parses a receipt's RFC 3339 date; nil when Foundation would not parse it.
///
/// The fast path takes only `yyyy-MM-ddTHH:mm:ssZ`, year 1970 through 9999,
/// with every field in its calendar range: an instant with one meaning and
/// whole seconds, which Foundation parses to the same `Date`. Anything else —
/// fractional seconds, an offset, a leap second, February 30th, a lowercase
/// `z` — falls through to ``parseReceiptDateWithFoundation(_:)``.
func parseReceiptDate(_ text: String) -> Date? {
    if let seconds = canonicalUTCSeconds(text) {
        return Date(timeIntervalSince1970: TimeInterval(seconds))
    }
    return parseReceiptDateWithFoundation(text)
}

/// The Foundation path, unchanged from before the fast path existed.
/// Internal so the differential test can compare the two.
func parseReceiptDateWithFoundation(_ text: String) -> Date? {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    if let date = formatter.date(from: text) {
        return date
    }
    formatter.formatOptions = [.withInternetDateTime]
    return formatter.date(from: text)
}

private func canonicalUTCSeconds(_ text: String) -> Int? {
    let bytes = text.utf8
    guard bytes.count == 20 else { return nil }
    var digits: [Int] = []
    digits.reserveCapacity(14)
    for (offset, byte) in bytes.enumerated() {
        switch offset {
        case 4, 7:
            guard byte == UInt8(ascii: "-") else { return nil }
        case 10:
            guard byte == UInt8(ascii: "T") else { return nil }
        case 13, 16:
            guard byte == UInt8(ascii: ":") else { return nil }
        case 19:
            guard byte == UInt8(ascii: "Z") else { return nil }
        default:
            guard byte >= UInt8(ascii: "0"), byte <= UInt8(ascii: "9") else { return nil }
            digits.append(Int(byte - UInt8(ascii: "0")))
        }
    }
    let year = digits[0] * 1000 + digits[1] * 100 + digits[2] * 10 + digits[3]
    let month = digits[4] * 10 + digits[5]
    let day = digits[6] * 10 + digits[7]
    let hour = digits[8] * 10 + digits[9]
    let minute = digits[10] * 10 + digits[11]
    let second = digits[12] * 10 + digits[13]
    guard year >= 1970, (1...12).contains(month), day >= 1,
        day <= daysInMonth(year, month), hour < 24, minute < 60, second < 60
    else { return nil }
    return daysFromCivil(year, month, day) * secondsPerDay + hour * 3600 + minute * 60 + second
}

/// Apple's `x` rendering, `yyyy-MM-dd HH:mm:ss Etc/GMT`.
func appleGMTString(_ date: Date) -> String {
    appleDateString(date, pacific: false) + " Etc/GMT"
}

/// Apple's `x_pst` rendering, `yyyy-MM-dd HH:mm:ss America/Los_Angeles`.
func applePacificString(_ date: Date) -> String {
    appleDateString(date, pacific: true) + " America/Los_Angeles"
}

/// 2007-01-01T08:00:00Z (midnight PST) up to, not including,
/// 9999-12-31T00:00:00Z, which leaves room for the -08:00 shift. The same
/// range as the Node port's node/src/apple-date.ts.
private let firstRuleSecond: TimeInterval = 1_167_638_400
private let lastRuleSecond: TimeInterval = 253_402_214_400

/// `yyyy-MM-dd HH:mm:ss` in UTC or in America/Los_Angeles.
///
/// From 2007 through 9999 the Pacific offset is the US daylight-saving rule
/// in force since 2007, which the tz database also projects forward: PDT
/// (-07:00) from the second Sunday of March at 02:00 PST to the first Sunday
/// of November at 02:00 PDT, PST (-08:00) otherwise. Outside that range, and
/// for a NaN or infinite instant (the comparisons below are false for NaN),
/// ``foundationAppleDateString(_:pacific:)`` answers as before.
///
/// The arithmetic follows `DateFormatter`'s, step for step in `Double`:
/// CFDateFormatter hands ICU `(seconds since 1970) * 1000 + 0.5`, so an
/// instant rounds to the NEAREST millisecond, and ICU adds the zone offset
/// and floors before taking any field. A request date a fraction of a
/// millisecond below a whole second therefore renders as the next second,
/// exactly as Foundation renders it.
func appleDateString(_ date: Date, pacific: Bool) -> String {
    let seconds = date.timeIntervalSince1970
    guard seconds >= firstRuleSecond, seconds < lastRuleSecond else {
        return foundationAppleDateString(date, pacific: pacific)
    }
    let millis = seconds * 1000 + 0.5
    var offsetMillis = 0
    if pacific {
        let standardMillis = Int((millis - 8 * 3_600_000).rounded(.down))
        let (year, _, _) = civilFromDays(floorDivide(standardMillis, secondsPerDay * 1000))
        // 02:00 PST is 10:00 UTC; 02:00 PDT is 09:00 UTC.
        let dstStart = (daysFromCivil(year, 3, nthSunday(year, 3, 2)) * secondsPerDay + 10 * 3600) * 1000
        let dstEnd = (daysFromCivil(year, 11, nthSunday(year, 11, 1)) * secondsPerDay + 9 * 3600) * 1000
        let daylight = millis >= Double(dstStart) && millis < Double(dstEnd)
        offsetMillis = (daylight ? -7 : -8) * 3_600_000
    }
    let localMillis = Int((millis + Double(offsetMillis)).rounded(.down))
    let localSeconds = floorDivide(localMillis, 1000)
    let (year, month, day) = civilFromDays(floorDivide(localSeconds, secondsPerDay))
    let secondOfDay = localSeconds - floorDivide(localSeconds, secondsPerDay) * secondsPerDay
    var out: [UInt8] = []
    out.reserveCapacity(19)
    func put(_ value: Int, _ width: Int) {
        var divisor = 1
        for _ in 1..<width { divisor *= 10 }
        while divisor > 0 {
            out.append(UInt8(ascii: "0") + UInt8(value / divisor % 10))
            divisor /= 10
        }
    }
    put(year, 4)
    out.append(UInt8(ascii: "-"))
    put(month, 2)
    out.append(UInt8(ascii: "-"))
    put(day, 2)
    out.append(UInt8(ascii: " "))
    put(secondOfDay / 3600, 2)
    out.append(UInt8(ascii: ":"))
    put(secondOfDay / 60 % 60, 2)
    out.append(UInt8(ascii: ":"))
    put(secondOfDay % 60, 2)
    return String(decoding: out, as: UTF8.self)
}

/// The Foundation rendering, unchanged from before the arithmetic path
/// existed: a new formatter per call, so nothing is shared between threads.
/// Internal so the differential test can compare the two.
func foundationAppleDateString(_ date: Date, pacific: Bool) -> String {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = TimeZone(identifier: pacific ? "America/Los_Angeles" : "UTC")!
    formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
    return formatter.string(from: date)
}

private func floorDivide(_ value: Int, _ divisor: Int) -> Int {
    let quotient = value / divisor
    return value % divisor < 0 ? quotient - 1 : quotient
}

private func isLeapYear(_ year: Int) -> Bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

private func daysInMonth(_ year: Int, _ month: Int) -> Int {
    switch month {
    case 2: return isLeapYear(year) ? 29 : 28
    case 4, 6, 9, 11: return 30
    default: return 31
    }
}

/// Days from 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
private func daysFromCivil(_ year: Int, _ month: Int, _ day: Int) -> Int {
    let y = month <= 2 ? year - 1 : year
    let era = floorDivide(y, 400)
    let yearOfEra = y - era * 400
    let dayOfYear = (153 * ((month + 9) % 12) + 2) / 5 + day - 1
    let dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear
    return era * 146_097 + dayOfEra - 719_468
}

/// The inverse of ``daysFromCivil(_:_:_:)`` (`civil_from_days`).
private func civilFromDays(_ days: Int) -> (year: Int, month: Int, day: Int) {
    let shifted = days + 719_468
    let era = floorDivide(shifted, 146_097)
    let dayOfEra = shifted - era * 146_097
    let yearOfEra = (dayOfEra - dayOfEra / 1460 + dayOfEra / 36524 - dayOfEra / 146_096) / 365
    let dayOfYear = dayOfEra - (365 * yearOfEra + yearOfEra / 4 - yearOfEra / 100)
    let shiftedMonth = (5 * dayOfYear + 2) / 153
    let day = dayOfYear - (153 * shiftedMonth + 2) / 5 + 1
    let month = shiftedMonth < 10 ? shiftedMonth + 3 : shiftedMonth - 9
    return (yearOfEra + era * 400 + (month <= 2 ? 1 : 0), month, day)
}

/// Day of the month of the `n`th Sunday of `month`.
private func nthSunday(_ year: Int, _ month: Int, _ n: Int) -> Int {
    // 1970-01-01 was a Thursday: weekday 4 when Sunday is 0.
    let firstWeekday = (daysFromCivil(year, month, 1) % 7 + 11) % 7
    return 1 + (7 - firstWeekday) % 7 + 7 * (n - 1)
}
