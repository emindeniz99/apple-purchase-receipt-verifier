using System;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>
    /// Parses a receipt date attribute's exact grammar: <c>YYYY-MM-DDTHH:MM:SSZ</c>
    /// — a four-digit year 0000 to 9999, uppercase <c>T</c> and <c>Z</c>, a real
    /// calendar date (leap years included), hours 00 to 23, minutes and seconds
    /// 00 to 59, no fraction and no offset (docs/design/0.7-api.md, Reading
    /// certificates and signed attributes).
    /// </summary>
    /// <remarks>
    /// Hand-written rather than <see cref="DateTimeOffset.TryParse(string, out DateTimeOffset)"/>
    /// or <c>DateTimeOffset.TryParseExact</c>: <see cref="DateTime"/>'s year
    /// range starts at 1, so year <c>0000</c>, which the grammar explicitly
    /// allows, is not representable through it. The day count uses Howard
    /// Hinnant's <c>days_from_civil</c> algorithm, which both validates the
    /// calendar date and converts it, with no <see cref="DateTime"/> involved.
    /// </remarks>
    internal static class ReceiptDate
    {
        private static readonly int[] DaysInMonth = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

        /// <summary>Parses <paramref name="text"/>, returning epoch milliseconds on success.</summary>
        internal static bool TryParse(string text, out long epochMilliseconds)
        {
            epochMilliseconds = 0;
            if (text.Length != 20)
            {
                return false;
            }

            if (!IsDigit(text, 0) || !IsDigit(text, 1) || !IsDigit(text, 2) || !IsDigit(text, 3)
                || text[4] != '-'
                || !IsDigit(text, 5) || !IsDigit(text, 6)
                || text[7] != '-'
                || !IsDigit(text, 8) || !IsDigit(text, 9)
                || text[10] != 'T'
                || !IsDigit(text, 11) || !IsDigit(text, 12)
                || text[13] != ':'
                || !IsDigit(text, 14) || !IsDigit(text, 15)
                || text[16] != ':'
                || !IsDigit(text, 17) || !IsDigit(text, 18)
                || text[19] != 'Z')
            {
                return false;
            }

            int year = TwoDigit(text, 0) * 100 + TwoDigit(text, 2);
            int month = TwoDigit(text, 5);
            int day = TwoDigit(text, 8);
            int hour = TwoDigit(text, 11);
            int minute = TwoDigit(text, 14);
            int second = TwoDigit(text, 17);

            if (hour > 23 || minute > 59 || second > 59)
            {
                return false;
            }

            if (!TryDaysFromCivil(year, month, day, out long days))
            {
                return false;
            }

            long totalSeconds = (days * 86400L) + (hour * 3600L) + (minute * 60L) + second;
            epochMilliseconds = totalSeconds * 1000L;
            return true;
        }

        private static bool IsDigit(string text, int index) => text[index] >= '0' && text[index] <= '9';

        private static int TwoDigit(string text, int index) => ((text[index] - '0') * 10) + (text[index + 1] - '0');

        private static bool IsLeapYear(int year) => year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);

        /// <summary>Days since the Unix epoch (1970-01-01) for a real calendar date, or <see langword="false"/> if it is not one.</summary>
        private static bool TryDaysFromCivil(int year, int month, int day, out long days)
        {
            days = 0;
            if (month < 1 || month > 12)
            {
                return false;
            }

            int daysInMonth = DaysInMonth[month - 1] + (month == 2 && IsLeapYear(year) ? 1 : 0);
            if (day < 1 || day > daysInMonth)
            {
                return false;
            }

            long y = year - (month <= 2 ? 1 : 0);
            long era = (y >= 0 ? y : y - 399) / 400;
            long yearOfEra = y - (era * 400);
            long dayOfYear = (((153L * (month + (month > 2 ? -3 : 9))) + 2) / 5) + day - 1;
            long dayOfEra = (yearOfEra * 365) + (yearOfEra / 4) - (yearOfEra / 100) + dayOfYear;
            days = (era * 146097) + dayOfEra - 719468;
            return true;
        }
    }
}
