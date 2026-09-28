package applereceipt

import "fmt"

// Calendar arithmetic and Apple's date renderings, with no dependency on
// the IANA time zone database.
//
// VerifyReceiptEndpoint renders every date three ways: x in GMT, x_ms in
// epoch milliseconds and x_pst in US Pacific time. The 0.7 design gives a
// Verifier no timezone-database override (unlike 0.6's
// VerifyReceiptEndpointOptions.PacificLocation): a compiled Go binary does
// not carry $GOROOT/lib/time/zoneinfo.zip, and a FROM scratch or
// distroless image has no /usr/share/zoneinfo either, so time.LoadLocation
// is not dependable here. The rule is closed-form instead, ported from the
// Rust reference's datetime.rs, which carries the same requirement: no
// dependency, exact against the IANA database.

const millisPerDay = 86_400_000
const secondsPerDay int64 = 86_400

// daysFromCivil is Howard Hinnant's days_from_civil: days since
// 1970-01-01 for a proleptic-Gregorian civil date.
func daysFromCivil(year, month, day int64) int64 {
	y := year
	if month <= 2 {
		y--
	}
	era := y
	if y < 0 {
		era = y - 399
	}
	era /= 400
	yoe := y - era*400
	mp := (month + 9) % 12
	doy := (153*mp+2)/5 + day - 1
	doe := yoe*365 + yoe/4 - yoe/100 + doy
	return era*146_097 + doe - 719_468
}

// civilFromDays is the inverse of daysFromCivil.
func civilFromDays(days int64) (year, month, day int64) {
	z := days + 719_468
	era := z
	if z < 0 {
		era = z - 146_096
	}
	era /= 146_097
	doe := z - era*146_097
	yoe := (doe - doe/1460 + doe/36_524 - doe/146_096) / 365
	y := yoe + era*400
	doy := doe - (365*yoe + yoe/4 - yoe/100)
	mp := (5*doy + 2) / 153
	d := doy - (153*mp+2)/5 + 1
	m := mp + 3
	if mp >= 10 {
		m = mp - 9
	}
	if m <= 2 {
		y++
	}
	return y, m, d
}

func weekdayFromDays(days int64) int64 {
	if days >= -4 {
		return (days + 4) % 7
	}
	return (days+5)%7 + 6
}

func isLeapCivil(year int64) bool {
	return (year%4 == 0 && year%100 != 0) || year%400 == 0
}

func daysInMonthCivil(year, month int64) int64 {
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		if isLeapCivil(year) {
			return 29
		}
		return 28
	default:
		return 0
	}
}

type civil struct {
	year, month, day, hour, minute, second, millis int64
}

func civilFromMillis(millis int64) civil {
	days := floorDiv(millis, millisPerDay)
	rem := floorMod(millis, millisPerDay)
	year, month, day := civilFromDays(days)
	return civil{
		year: year, month: month, day: day,
		hour: rem / 3_600_000, minute: (rem / 60_000) % 60,
		second: (rem / 1_000) % 60, millis: rem % 1_000,
	}
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		q--
	}
	return q
}

func floorMod(a, b int64) int64 {
	return a - floorDiv(a, b)*b
}

// pstOffsetSeconds and pdtOffsetSeconds are UTC-8 and UTC-7.
const pstOffsetSeconds int64 = -8 * 3600
const pdtOffsetSeconds int64 = -7 * 3600

// regularRulesFrom is 1967-01-01T00:00:00Z. From here on the transitions
// follow rules simple enough to state in closed form; before it they do
// not.
const regularRulesFrom int64 = -94_694_400

// preTransitions is every US-Pacific offset change from 1900 up to
// regularRulesFrom, as (UTC second, offset). This era is a table rather
// than a rule because it genuinely is not one: wartime daylight time ran
// continuously from February 1942 to September 1945, 1948 was a single
// year of it, and from 1950 to 1966 the start and end were 01:00 local
// rather than the 02:00 every later rule uses, with the end moving from
// September to October in 1962. Transcribed from the IANA database,
// ported verbatim from the Rust reference implementation's
// PRE_1967_TRANSITIONS.
var preTransitions = [...]struct {
	at     int64
	offset int64
}{
	{-1_633_269_600, pdtOffsetSeconds}, // 1918-03-31 10:00:00Z
	{-1_615_129_200, pstOffsetSeconds}, // 1918-10-27 09:00:00Z
	{-1_601_820_000, pdtOffsetSeconds}, // 1919-03-30 10:00:00Z
	{-1_583_679_600, pstOffsetSeconds}, // 1919-10-26 09:00:00Z
	{-880_207_200, pdtOffsetSeconds},   // 1942-02-09 10:00:00Z
	{-765_385_200, pstOffsetSeconds},   // 1945-09-30 09:00:00Z
	{-687_967_140, pdtOffsetSeconds},   // 1948-03-14 10:01:00Z
	{-662_655_600, pstOffsetSeconds},   // 1949-01-01 09:00:00Z
	{-620_838_000, pdtOffsetSeconds},   // 1950-04-30 09:00:00Z
	{-608_137_200, pstOffsetSeconds},   // 1950-09-24 09:00:00Z
	{-589_388_400, pdtOffsetSeconds},   // 1951-04-29 09:00:00Z
	{-576_082_800, pstOffsetSeconds},   // 1951-09-30 09:00:00Z
	{-557_938_800, pdtOffsetSeconds},   // 1952-04-27 09:00:00Z
	{-544_633_200, pstOffsetSeconds},   // 1952-09-28 09:00:00Z
	{-526_489_200, pdtOffsetSeconds},   // 1953-04-26 09:00:00Z
	{-513_183_600, pstOffsetSeconds},   // 1953-09-27 09:00:00Z
	{-495_039_600, pdtOffsetSeconds},   // 1954-04-25 09:00:00Z
	{-481_734_000, pstOffsetSeconds},   // 1954-09-26 09:00:00Z
	{-463_590_000, pdtOffsetSeconds},   // 1955-04-24 09:00:00Z
	{-450_284_400, pstOffsetSeconds},   // 1955-09-25 09:00:00Z
	{-431_535_600, pdtOffsetSeconds},   // 1956-04-29 09:00:00Z
	{-418_230_000, pstOffsetSeconds},   // 1956-09-30 09:00:00Z
	{-400_086_000, pdtOffsetSeconds},   // 1957-04-28 09:00:00Z
	{-386_780_400, pstOffsetSeconds},   // 1957-09-29 09:00:00Z
	{-368_636_400, pdtOffsetSeconds},   // 1958-04-27 09:00:00Z
	{-355_330_800, pstOffsetSeconds},   // 1958-09-28 09:00:00Z
	{-337_186_800, pdtOffsetSeconds},   // 1959-04-26 09:00:00Z
	{-323_881_200, pstOffsetSeconds},   // 1959-09-27 09:00:00Z
	{-305_737_200, pdtOffsetSeconds},   // 1960-04-24 09:00:00Z
	{-292_431_600, pstOffsetSeconds},   // 1960-09-25 09:00:00Z
	{-273_682_800, pdtOffsetSeconds},   // 1961-04-30 09:00:00Z
	{-260_982_000, pstOffsetSeconds},   // 1961-09-24 09:00:00Z
	{-242_233_200, pdtOffsetSeconds},   // 1962-04-29 09:00:00Z
	{-226_508_400, pstOffsetSeconds},   // 1962-10-28 09:00:00Z
	{-210_783_600, pdtOffsetSeconds},   // 1963-04-28 09:00:00Z
	{-195_058_800, pstOffsetSeconds},   // 1963-10-27 09:00:00Z
	{-179_334_000, pdtOffsetSeconds},   // 1964-04-26 09:00:00Z
	{-163_609_200, pstOffsetSeconds},   // 1964-10-25 09:00:00Z
	{-147_884_400, pdtOffsetSeconds},   // 1965-04-25 09:00:00Z
	{-131_554_800, pstOffsetSeconds},   // 1965-10-31 09:00:00Z
	{-116_434_800, pdtOffsetSeconds},   // 1966-04-24 09:00:00Z
	{-100_105_200, pstOffsetSeconds},   // 1966-10-30 09:00:00Z
}

// pacificOffsetSeconds is the UTC offset of America/Los_Angeles, in
// seconds, at an epoch-millisecond instant. Exact against the IANA
// database for every instant from 1900 onward.
//
// The rules, from 1967 on: since 2007, PDT from the second Sunday in
// March at 02:00 local standard time to the first Sunday in November at
// 02:00 local daylight time; 1987 to 2006, first Sunday in April to last
// Sunday in October; 1976 to 1986 and 1967 to 1973, last Sunday in April
// to last Sunday in October; 1975, 23 February to the last Sunday in
// October; 1974, 6 January to the last Sunday in October (1974 and 1975
// are the Emergency Daylight Saving Time Energy Conservation Act, not a
// pattern). Before 1967, preTransitions. Before 1900 the answer is PST.
func pacificOffsetSeconds(millis int64) int64 {
	seconds := floorDiv(millis, 1000)
	if seconds < regularRulesFrom {
		offset := pstOffsetSeconds
		for _, t := range preTransitions {
			if seconds < t.at {
				break
			}
			offset = t.offset
		}
		return offset
	}
	year, _, _ := civilFromDays(floorDiv(millis, millisPerDay))
	var startMonth, startDay, endMonth, endDay int64
	switch {
	case year >= 2007:
		startMonth, startDay = 3, nthWeekday(year, 3, 0, 2)
		endMonth, endDay = 11, nthWeekday(year, 11, 0, 1)
	case year >= 1987:
		startMonth, startDay = 4, nthWeekday(year, 4, 0, 1)
		endMonth, endDay = 10, lastWeekday(year, 10, 0)
	case year == 1975:
		startMonth, startDay = 2, 23
		endMonth, endDay = 10, lastWeekday(year, 10, 0)
	case year == 1974:
		startMonth, startDay = 1, 6
		endMonth, endDay = 10, lastWeekday(year, 10, 0)
	default:
		startMonth, startDay = 4, lastWeekday(year, 4, 0)
		endMonth, endDay = 10, lastWeekday(year, 10, 0)
	}
	// Transitions are expressed in UTC: 02:00 local standard time is
	// 10:00 UTC, and 02:00 local daylight time is 09:00 UTC.
	start := daysFromCivil(year, startMonth, startDay)*secondsPerDay + 10*3600
	end := daysFromCivil(year, endMonth, endDay)*secondsPerDay + 9*3600
	if seconds >= start && seconds < end {
		return pdtOffsetSeconds
	}
	return pstOffsetSeconds
}

// nthWeekday is the day-of-month of the nth weekday (0 = Sunday) of a
// month, 1-based n.
func nthWeekday(year, month, weekday, n int64) int64 {
	first := daysFromCivil(year, month, 1)
	shift := floorMod(weekday-weekdayFromDays(first), 7)
	return 1 + shift + (n-1)*7
}

// lastWeekday is the day-of-month of the last weekday (0 = Sunday) of a
// month.
func lastWeekday(year, month, weekday int64) int64 {
	last := daysInMonthCivil(year, month)
	lastDays := daysFromCivil(year, month, last)
	return last - floorMod(weekdayFromDays(lastDays)-weekday, 7)
}

// formatAppleDate renders Apple's x / x_pst form: "YYYY-MM-DD HH:MM:SS
// <label>", with the civil time taken at offsetSeconds from UTC.
func formatAppleDate(millis, offsetSeconds int64, label string) string {
	c := civilFromMillis(millis + offsetSeconds*1000)
	return fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d %s",
		c.year, c.month, c.day, c.hour, c.minute, c.second, label)
}
