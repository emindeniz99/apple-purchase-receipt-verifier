# frozen_string_literal: true

require_relative "helper"
require "tmpdir"
require "rbconfig"

# Graduation lessons 1 and 15, mechanised: test the artifact the consumer
# receives, not a proxy for it. The Ruby shape of the two broken npm releases
# is `spec.files` losing `certs/` — a gem that installs and requires cleanly
# and then raises the first time anyone asks for a trust anchor.
#
# Skipped unless APRV_PACKAGING=1, because it shells out to `gem build` and
# `gem install`; CI's gem job sets it.
class PackagingTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier

  REQUIRED_FILES = [
    "lib/apple_purchase_receipt_verifier.rb",
    "lib/apple-purchase-receipt-verifier.rb",
    "certs/AppleIncRootCertificate.cer",
    "certs/AppleRootCA-G2.cer",
    "certs/AppleRootCA-G3.cer",
    "README.md",
    "LICENSE"
  ].freeze

  def root
    File.expand_path("..", __dir__)
  end

  # This half needs no shell and always runs: the gemspec's file list is
  # evaluated directly.
  def test_the_gemspec_declares_every_file_a_consumer_needs
    spec = Gem::Specification.load(File.join(root, "apple-purchase-receipt-verifier.gemspec"))
    refute_nil spec, "the gemspec does not load"
    REQUIRED_FILES.each { |path| assert_includes spec.files, path }
    assert_empty spec.runtime_dependencies, "the library must have no runtime dependencies"
    assert_equal APRV::VERSION, spec.version.to_s
    assert_equal Gem::Requirement.new(">= 3.1.0"), spec.required_ruby_version
  end

  def test_the_gemspec_ships_no_test_or_tooling_files
    spec = Gem::Specification.load(File.join(root, "apple-purchase-receipt-verifier.gemspec"))
    spec.files.each do |path|
      refute_match(%r{\Atest/}, path)
      refute_match(%r{\Agemfiles/}, path)
      refute_match(/Gemfile|Rakefile|\.rubocop/, path)
    end
  end

  def test_the_built_gem_verifies_a_genuine_receipt_from_a_clean_gem_home
    skip "set APRV_PACKAGING=1 to run the gem build/install round trip" unless ENV["APRV_PACKAGING"]

    Dir.mktmpdir("aprv-packaging") do |workspace|
      gem_home = File.join(workspace, "gems")
      built = build_gem(workspace)
      run!("gem", "install", "--no-document", "--install-dir", gem_home, built)
      ruby = RbConfig.ruby
      output = run!(ruby, File.join(root, "script", "consumer_smoke.rb"),
                    TestSupport.fixtures_root,
                    env: { "GEM_HOME" => gem_home, "GEM_PATH" => gem_home, "RUBYOPT" => nil })
      assert_match(/^ok: apple-purchase-receipt-verifier /, output)
    end
  end

  private

  def build_gem(workspace)
    Dir.chdir(root) do
      run!("gem", "build", "apple-purchase-receipt-verifier.gemspec", "--output",
           File.join(workspace, "built.gem"))
    end
    File.join(workspace, "built.gem")
  end

  def run!(*command, env: {})
    require "open3"
    output, status = Open3.capture2e(env.transform_values { |v| v }, *command)
    raise "command failed: #{command.join(" ")}\n#{output}" unless status.success?

    output
  end
end
