# frozen_string_literal: true

require "openssl"

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "apple_purchase_receipt_verifier"

# Shared support for the ruzzy targets in this directory: where the shared
# fixtures are, the anchors a target pins, and the one assertion every target
# makes about which errors an entry point is allowed to raise.
#
# Loaded from inside a target rather than from the tracer on purpose. Ruzzy
# turns on branch coverage and only then requires the target, so anything
# required before that point is compiled without coverage instrumentation and
# is invisible to the fuzzer. Requiring the library from here is what puts it
# under coverage.
module FuzzSupport
  APRV = ApplePurchaseReceiptVerifier

  # Raised when a target's invariant is broken. Nothing rescues it: it unwinds
  # out of the libFuzzer callback, Ruby exits, and libFuzzer writes the input
  # that did it under the artifact prefix.
  class InvariantViolated < RuntimeError; end

  # The process being asked to stop is not a finding.
  CONTROL = [SystemExit, Interrupt, SignalException].freeze

  # Never raised by anything, so `rescue NoError` never matches. A target
  # hands this to {call} to say "this entry point may not raise at all" —
  # which is the verifyReceipt endpoint's contract.
  class NoError < StandardError; end

  class << self
    # The repository's shared fixtures directory. Walked up to rather than
    # counted in "../.." levels, so the harness keeps working wherever it is
    # run from — the same rule test/helper.rb follows.
    def fixtures_root
      @fixtures_root ||= find_fixtures_root
    end

    # @param relative [String] a path under fixtures/, e.g. "generated/jws-root.der"
    def fixture_certificate(relative)
      OpenSSL::X509::Certificate.new(File.binread(File.join(fixtures_root, relative)))
    end

    # Runs one library call and says whether it accepted or rejected.
    #
    # `allowed` is the error class that entry point documents. Anything else —
    # a NoMethodError from a nil the parser did not expect, a TypeError, a
    # SystemStackError from unbounded recursion — is the finding this whole
    # exercise exists to catch, so it is re-raised as {InvariantViolated} and
    # takes the process, and with it the offending input, down.
    #
    # @return [Array(Symbol, Object)] `[:accepted, value]` or `[:rejected, nil]`
    def call(what, allowed)
      [:accepted, yield]
    rescue *CONTROL
      raise
    rescue allowed
      [:rejected, nil]
    rescue Exception => e # rubocop:disable Lint/RescueException
      # Deliberately broader than StandardError: SystemStackError and
      # NoMemoryError are exactly the escapes a bounded parser exists to
      # prevent, and neither is a StandardError.
      violated("#{what} escaped as #{e.class}: #{e.message}", e)
    end

    def violated(message, cause = nil)
      frames = Array(cause&.backtrace).first(12)
      detail = frames.empty? ? "" : "\n  at #{frames.join("\n  at ")}"
      raise InvariantViolated, "#{message}#{detail}"
    end

    private

    def find_fixtures_root
      directory = __dir__
      12.times do
        candidate = File.join(directory, "fixtures")
        return candidate if File.file?(File.join(candidate, "cases.json"))

        parent = File.dirname(directory)
        break if parent == directory

        directory = parent
      end
      raise "harness error: could not locate fixtures/cases.json above #{__dir__}"
    end
  end
end
