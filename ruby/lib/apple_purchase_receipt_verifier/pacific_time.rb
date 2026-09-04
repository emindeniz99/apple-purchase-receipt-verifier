# frozen_string_literal: true

module ApplePurchaseReceiptVerifier
  # US Pacific wall-clock rendering for the `*_pst` fields of the
  # verifyReceipt-compatible response.
  #
  # Ruby has no time-zone database in its standard library, and `tzinfo` would
  # be a runtime dependency in a security library, so this port computes the
  # America/Los_Angeles offset from the published US rules. That makes it the
  # one piece of the port with no platform library behind it; it is tested
  # against both sides of, and the exact instants of, every rule change below.
  #
  # `Time#getlocal("-08:00")` is not an answer: a fixed offset is wrong for
  # half the year. Shelling out to `TZ=America/Los_Angeles` is not one either —
  # it depends on the host's tzdata and cannot be tested deterministically.
  #
  # Rules (US federal law, Pacific zone; all transition times are 02:00 local):
  #
  # * 2007-      second Sunday in March .. first Sunday in November
  # * 1987-2006  first Sunday in April  .. last Sunday in October
  # * 1976-1986  last Sunday in April   .. last Sunday in October
  #
  # Before 1976 the zone's history stops being a simple rule; those instants
  # render as standard time. No Apple receipt predates the App Store (2008).
  #
  # @api private
  module PacificTime
    STANDARD_OFFSET = -8 * 3600
    DAYLIGHT_OFFSET = -7 * 3600

    ZONE_LABEL = "America/Los_Angeles"

    class << self
      # @param time [Time]
      # @return [Time] the same instant, shifted to Pacific wall-clock
      def wall_clock(time)
        time.getlocal(offset(time))
      end

      # @return [Integer] seconds east of UTC at `time`
      def offset(time)
        utc = time.utc? ? time : time.getutc
        year = utc.year
        start_at, end_at = daylight_window(year)
        return STANDARD_OFFSET if start_at.nil?

        utc >= start_at && utc < end_at ? DAYLIGHT_OFFSET : STANDARD_OFFSET
      end

      private

      # The two UTC instants bounding daylight time in `year`, or nil when the
      # year predates the rules modelled here.
      def daylight_window(year)
        if year >= 2007
          # 02:00 PST = 10:00 UTC on the second Sunday in March;
          # 02:00 PDT = 09:00 UTC on the first Sunday in November.
          [transition(year, 3, nth_sunday(year, 3, 2), 10),
           transition(year, 11, nth_sunday(year, 11, 1), 9)]
        elsif year >= 1987
          [transition(year, 4, nth_sunday(year, 4, 1), 10),
           transition(year, 10, last_sunday(year, 10), 9)]
        elsif year >= 1976
          [transition(year, 4, last_sunday(year, 4), 10),
           transition(year, 10, last_sunday(year, 10), 9)]
        else
          [nil, nil]
        end
      end

      def transition(year, month, day, utc_hour)
        Time.utc(year, month, day, utc_hour)
      end

      def nth_sunday(year, month, nth)
        first = Time.utc(year, month, 1)
        # Time#wday: 0 is Sunday.
        day = 1 + ((7 - first.wday) % 7)
        day + ((nth - 1) * 7)
      end

      def last_sunday(year, month)
        day = days_in_month(year, month)
        last = Time.utc(year, month, day)
        day - last.wday
      end

      def days_in_month(year, month)
        return 31 if month == 12

        (Time.utc(year, month + 1, 1) - 86_400).day
      end
    end
  end
end
