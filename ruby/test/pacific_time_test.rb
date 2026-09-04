# frozen_string_literal: true

require_relative "helper"

# The `*_pst` rendering of the verifyReceipt-compatible response.
#
# Ruby ships no time-zone database, so this is the one piece of the port with
# no platform library behind it. These vectors were produced from the IANA
# database (Python's `zoneinfo`, America/Los_Angeles) and are checked in as the
# reference, exactly so the hand-rolled rule is measured against tzdata rather
# than against itself. They cover every US rule change since 1976 plus both
# sides of, and the exact instant of, each recent transition.
class PacificTimeTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier

  VECTORS = [
    # pre-2007 rule (first Sunday in April .. last Sunday in October)
    ["1999-01-15T12:00:00Z", "1999-01-15 04:00:00"],
    ["1999-07-15T12:00:00Z", "1999-07-15 05:00:00"],
    ["2006-04-02T09:59:59Z", "2006-04-02 01:59:59"],
    ["2006-04-02T10:00:00Z", "2006-04-02 03:00:00"],
    ["2006-10-29T08:59:59Z", "2006-10-29 01:59:59"],
    ["2006-10-29T09:00:00Z", "2006-10-29 01:00:00"],
    ["1988-04-03T09:59:59Z", "1988-04-03 01:59:59"],
    ["1988-04-03T10:00:00Z", "1988-04-03 03:00:00"],
    ["1988-10-30T08:59:59Z", "1988-10-30 01:59:59"],
    ["1988-10-30T09:00:00Z", "1988-10-30 01:00:00"],
    # 1976-1986 rule (last Sunday in April)
    ["1980-04-27T09:59:59Z", "1980-04-27 01:59:59"],
    ["1980-04-27T10:00:00Z", "1980-04-27 03:00:00"],
    # 2007- rule (second Sunday in March .. first Sunday in November)
    ["2007-03-11T09:59:59Z", "2007-03-11 01:59:59"],
    ["2007-03-11T10:00:00Z", "2007-03-11 03:00:00"],
    ["2007-11-04T08:59:59Z", "2007-11-04 01:59:59"],
    ["2007-11-04T09:00:00Z", "2007-11-04 01:00:00"],
    ["2008-07-11T00:00:00Z", "2008-07-10 17:00:00"],
    ["2013-03-10T10:00:00Z", "2013-03-10 03:00:00"],
    ["2016-11-06T09:00:00Z", "2016-11-06 01:00:00"],
    ["2024-03-10T09:59:59Z", "2024-03-10 01:59:59"],
    ["2024-03-10T10:00:00Z", "2024-03-10 03:00:00"],
    ["2024-08-06T12:00:00Z", "2024-08-06 05:00:00"],
    ["2024-11-03T08:59:59Z", "2024-11-03 01:59:59"],
    ["2024-11-03T09:00:00Z", "2024-11-03 01:00:00"],
    ["2025-01-01T00:00:00Z", "2024-12-31 16:00:00"],
    ["2030-02-01T09:30:00Z", "2030-02-01 01:30:00"],
    ["2035-06-15T18:45:12Z", "2035-06-15 11:45:12"],
    ["2099-01-01T00:00:00Z", "2098-12-31 16:00:00"],
    ["2099-07-01T00:00:00Z", "2099-06-30 17:00:00"]
  ].freeze

  def test_every_tzdata_vector_renders_identically
    VECTORS.each do |iso, expected|
      rendered = APRV::PacificTime.wall_clock(Time.iso8601(iso).utc).strftime("%Y-%m-%d %H:%M:%S")
      assert_equal expected, rendered, iso
    end
  end

  def test_the_offset_is_only_ever_seven_or_eight_hours_west
    (0..(365 * 4)).each do |day|
      instant = Time.utc(2022, 1, 1) + (day * 86_400)
      assert_includes [-8 * 3600, -7 * 3600], APRV::PacificTime.offset(instant)
    end
  end

  # A fixed offset is wrong for half the year; this is why `Time#getlocal("-08:00")`
  # is not an implementation of this.
  def test_the_offset_actually_changes_across_a_year
    offsets = (0..11).map { |month| APRV::PacificTime.offset(Time.utc(2024, month + 1, 20)) }
    assert_equal 2, offsets.uniq.size
  end

  # Both US transitions are defined as happening on a Sunday, at 02:00 local.
  def test_transitions_land_on_a_sunday_at_two_am_local
    (2007..2040).each do |year|
      changes = (0..(366 * 24)).map { |h| Time.utc(year, 1, 1) + (h * 3600) }
                               .each_cons(2)
                               .reject { |a, b| APRV::PacificTime.offset(a) == APRV::PacificTime.offset(b) }
                               .map(&:last)
      assert_equal 2, changes.size, "#{year} should have two transitions"
      changes.each do |instant|
        local = APRV::PacificTime.wall_clock(instant)
        assert_equal 0, local.wday, "#{year}: #{local} is not a Sunday"
        assert_includes [1, 3], local.hour, "#{year}: #{local} is not a 02:00 local transition"
      end
    end
  end

  def test_a_non_utc_time_is_converted_before_the_rule_is_applied
    instant = Time.iso8601("2024-08-06T12:00:00Z").getlocal("+05:30")
    assert_equal "2024-08-06 05:00:00",
                 APRV::PacificTime.wall_clock(instant).strftime("%Y-%m-%d %H:%M:%S")
  end
end
