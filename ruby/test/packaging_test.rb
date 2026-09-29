# frozen_string_literal: true

require_relative "helper"
require "tmpdir"
require "rbconfig"

# Graduation lessons 1 and 15, mechanised: test the artifact the consumer
# receives, not a proxy for it. The Ruby shape of the two broken npm releases
# is `spec.files` losing a file the code reads at run time — here aprv.wasm or
# its hash — a gem that installs and requires cleanly and then raises the
# first time anyone builds a verifier.
#
# Skipped unless APRV_PACKAGING=1, because it shells out to `gem build` and
# `gem install`; CI's gem job sets it.
class PackagingTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier

  REQUIRED_FILES = [
    "lib/apple_purchase_receipt_verifier.rb",
    "lib/apple-purchase-receipt-verifier.rb",
    "lib/apple_purchase_receipt_verifier/aprv.wasm",
    "lib/apple_purchase_receipt_verifier/aprv.wasm.sha256",
    "licenses/NOTICE",
    "licenses/openssl/LICENSE.txt",
    "licenses/wasi-libc/LICENSE",
    "licenses/wasi-libc/LICENSE-APACHE",
    "licenses/wasi-libc/LICENSE-APACHE-LLVM",
    "licenses/wasi-libc/LICENSE-MIT",
    "licenses/rust/LICENSE-MIT",
    "licenses/rust/LICENSE-APACHE",
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
    assert_equal ["wasmtime (>= 48.0.1)"], spec.runtime_dependencies.map(&:to_s),
                 "wasmtime is the one runtime dependency"
    assert_equal APRV::VERSION, spec.version.to_s
    assert_equal Gem::Requirement.new(">= 3.3.0"), spec.required_ruby_version
  end

  # Nothing that holds no purpose in the artifact: Apple's roots are inside
  # the module, so the certs and their inlined form stay out.
  def test_the_gemspec_ships_no_roots
    spec = Gem::Specification.load(File.join(root, "apple-purchase-receipt-verifier.gemspec"))
    spec.files.each do |path|
      refute_match(%r{\Acerts/}, path)
      refute_match(/roots_data/, path)
    end
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
      clean = { "GEM_HOME" => gem_home, "GEM_PATH" => gem_home, "RUBYOPT" => nil }
      install = run!("gem", "install", "--no-document", "--install-dir", gem_home, built, env: clean)
      # The prebuilt native wasmtime gem must resolve, so no Rust toolchain is
      # needed: RubyGems picked a platform gem, not the source gem.
      native = Dir[File.join(gem_home, "gems", "wasmtime-*")].map { |dir| File.basename(dir) }
      assert_equal 1, native.size, install
      assert_match(/\Awasmtime-\d+\.\d+\.\d+-\S+\z/, native.first,
                   "RubyGems installed the source gem: #{native.first}")
      warn "packaging: RubyGems picked #{native.first}"
      smoke = File.join(root, "script", "consumer_smoke.rb")
      output = run!(RbConfig.ruby, smoke, TestSupport.fixtures_root,
                    env: clean.merge("APRV_SMOKE_STANDIN" => ENV.fetch("APRV_SMOKE_STANDIN", nil)))
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

  # Runs a command outside Bundler's environment, which would otherwise
  # re-point RUBYOPT and GEM_HOME at the bundle and hide the clean gem home.
  def run!(*command, env: {})
    require "open3"
    output = status = nil
    unbundled do
      output, status = Open3.capture2e(env, *command)
    end
    raise "command failed: #{command.join(" ")}\n#{output}" unless status.success?

    output
  end

  def unbundled(&)
    return yield unless defined?(Bundler)

    Bundler.with_unbundled_env(&)
  end
end
