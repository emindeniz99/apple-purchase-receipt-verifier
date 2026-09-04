# frozen_string_literal: true

require "minitest/autorun"
require "json"
require "openssl"
require "time"
require "digest"

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "apple_purchase_receipt_verifier"

module TestSupport
  APRV = ApplePurchaseReceiptVerifier

  class << self
    # Walks up from this file rather than counting "../.." levels, so the
    # suite keeps working wherever it is run from.
    def fixtures_root
      @fixtures_root ||= begin
        directory = __dir__
        found = nil
        12.times do
          candidate = File.join(directory, "fixtures", "cases.json")
          if File.file?(candidate)
            found = File.join(directory, "fixtures")
            break
          end
          parent = File.dirname(directory)
          break if parent == directory

          directory = parent
        end
        raise "harness error: could not locate fixtures/cases.json" if found.nil?

        found
      end
    end

    def repo_root
      File.dirname(fixtures_root)
    end

    def cases
      @cases ||= JSON.parse(File.read(File.join(fixtures_root, "cases.json")))
    end

    # The decoded logical bytes of a registered fixture, checked against the
    # digest the registry records for them.
    #
    # contentSha256 is not documentation. A fixture that is regenerated,
    # re-encoded or quietly edited changes the bytes every port verifies, and
    # the pinned expectations would then describe something no other port ever
    # saw. Re-hashing here is what makes the guarantee load-bearing.
    def fixture_bytes(id)
      @fixture_cache ||= {}
      cached = @fixture_cache[id]
      return cached if cached

      entry = cases["fixtures"][id]
      raise "harness error: cases.json registers no fixture #{id.inspect}" if entry.nil?

      raw = File.binread(File.join(fixtures_root, entry["path"]))
      bytes =
        case entry["codec"]
        when "raw" then raw
        when "base64" then raw.gsub(/\s+/, "").unpack1("m")
        when "utf8" then raw.force_encoding(Encoding::UTF_8).strip.b
        else raise "harness error: unknown fixture codec #{entry["codec"].inspect}"
        end

      recorded = entry["contentSha256"]
      unless recorded.is_a?(String)
        raise "fixture #{id.inspect} (#{entry["path"]}) records no contentSha256"
      end

      actual = Digest::SHA256.hexdigest(bytes)
      unless actual == recorded
        raise "fixture #{id.inspect} (#{entry["path"]}, codec #{entry["codec"]}) has drifted: " \
              "cases.json records contentSha256 #{recorded}, the decoded bytes hash to #{actual}"
      end

      @fixture_cache[id] = bytes
    end

    def fixture_certificate(id)
      OpenSSL::X509::Certificate.new(fixture_bytes(id))
    end
  end
end
