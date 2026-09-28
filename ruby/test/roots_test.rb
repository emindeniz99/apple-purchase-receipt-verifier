# frozen_string_literal: true

require_relative "helper"

# The bundled trust anchors: which three, where they come from, that they
# are pinned by fingerprint, and that they cannot be poisoned by a caller.
class RootsTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier

  def certs_dir
    File.expand_path("../certs", __dir__)
  end

  def test_config_defaults_returns_all_three_published_apple_roots
    roots = APRV::Config.defaults.roots
    assert_equal 3, roots.size
    subjects = roots.map { |c| c.subject.to_a.assoc("CN")[1] }.sort
    assert_equal ["Apple Root CA", "Apple Root CA - G2", "Apple Root CA - G3"], subjects
  end

  # Cross-port rule S7: the anchors are inlined in the gem's own code, not
  # read from disk when a verifier is built, so the gem works from a
  # read-only or bundled deployment. This asserts the inlined bytes still
  # equal the files.
  def test_the_inlined_roots_equal_the_packaged_certificate_files
    on_disk = Dir.glob(File.join(certs_dir, "*.cer")).map { |p| File.binread(p) }
    inlined = APRV::APPLE_ROOT_DER_BASE64.map { |b64| b64.unpack1("m0") }
    assert_equal on_disk.sort, inlined.sort
  end

  def test_the_packaged_certificates_match_the_repository_roots
    repository = Dir.glob(File.join(TestSupport.repo_root, "certs", "*.cer"))
    skip "no repository certs/ directory next to fixtures/" if repository.empty?

    repository.each do |path|
      packaged = File.join(certs_dir, File.basename(path))
      assert_path_exists packaged
      assert_equal File.binread(path), File.binread(packaged), File.basename(path)
    end
  end

  # Roots.apple_roots checks each bundled DER against its pinned SHA-256
  # before it becomes an anchor: a `certs/` file regenerated from a swapped
  # source must not silently become a trust anchor.
  def test_every_bundled_root_matches_its_pinned_fingerprint
    APRV::APPLE_ROOT_DER_BASE64.zip(APRV::Roots::APPLE_ROOT_SHA256).each do |b64, fingerprint|
      assert_equal fingerprint, Digest::SHA256.hexdigest(b64.unpack1("m0"))
    end
  end

  def test_a_swapped_root_empties_the_whole_set_rather_than_silently_dropping_one
    swapped = APRV::APPLE_ROOT_DER_BASE64.dup
    swapped[0], swapped[1] = swapped[1], swapped[0]
    stub_const(APRV, :APPLE_ROOT_DER_BASE64, swapped.freeze) do
      assert_empty APRV::Roots.apple_roots
    end
  end

  def test_each_call_returns_fresh_certificate_objects_so_a_caller_cannot_poison_another_config
    first = APRV::Roots.apple_roots
    second = APRV::Roots.apple_roots
    refute_same first, second
    refute_same first[0], second[0]
  end

  def test_the_roots_are_self_signed_and_carry_ca_true
    APRV::Config.defaults.roots.each do |root|
      assert_equal root.subject.to_der, root.issuer.to_der
      assert APRV::Chain.ca?(root), "#{root.subject} is not a CA"
    end
  end

  # An anchor is trusted by fiat, so its expiry is never examined — but these
  # ones should also simply not be expired, and a surprise here is worth a
  # loud failure rather than a silent one.
  def test_the_bundled_roots_are_not_expired
    APRV::Config.defaults.roots.each do |root|
      assert_operator root.not_after, :>, Time.now, "#{root.subject} has expired"
    end
  end

  private

  # Swaps a constant for `value` for the duration of the block, restoring it
  # (and its original frozen-ness) afterwards even if the block raises.
  def stub_const(mod, name, value)
    original = mod.const_get(name)
    mod.send(:remove_const, name)
    mod.const_set(name, value)
    yield
  ensure
    mod.send(:remove_const, name)
    mod.const_set(name, original)
  end
end
