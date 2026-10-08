# frozen_string_literal: true

module ApplePurchaseReceiptVerifier
  VERSION = "0.10.0" # x-release-please-version

  # `Version.CURRENT` in docs/design/0.7-api.md, spelled the Ruby way: a
  # module method rather than a second constant, so there is exactly one
  # value release-please bumps.
  module Version
    class << self
      # @return [String] the current gem version, for startup logs
      def current
        VERSION
      end
    end
  end
end
