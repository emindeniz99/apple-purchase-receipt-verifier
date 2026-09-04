# frozen_string_literal: true

require_relative "helper"

# The bundled trust anchors: which three, where they come from, and that they
# cannot be poisoned by a caller.
class RootsTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier

  def certs_dir
    File.expand_path("../certs", __dir__)
  end

  def test_both_accessors_return_all_three_published_apple_roots
    [APRV.apple_jws_roots, APRV.apple_receipt_roots].each do |roots|
      assert_equal 3, roots.size
      subjects = roots.map { |c| c.subject.to_a.assoc("CN")[1] }.sort
      assert_equal ["Apple Root CA", "Apple Root CA - G2", "Apple Root CA - G3"], subjects
    end
  end

  # PLAN D15: the two sets are deliberately identical. Apple documents the JWS
  # chain as ending in "an Apple root certificate", not a specific one, so
  # narrowing either set would fail closed and silently the day Apple
  # re-anchored a path.
  def test_the_two_sets_are_the_same_three_roots
    jws = APRV.apple_jws_roots.map(&:to_der).sort
    receipt = APRV.apple_receipt_roots.map(&:to_der).sort
    assert_equal jws, receipt
  end

  # Cross-port rule S7: the anchors are inlined in the gem's own code, not read
  # from disk when a verifier is built, so the gem works from a read-only or
  # bundled deployment. This asserts the inlined bytes still equal the files.
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

  def test_each_call_returns_fresh_objects_so_a_caller_cannot_poison_another_verifier
    first = APRV.apple_jws_roots
    second = APRV.apple_jws_roots
    refute_same first, second
    refute_same first[0], second[0]

    first.clear
    assert_equal 3, APRV.apple_jws_roots.size
  end

  def test_the_roots_are_self_signed_and_carry_ca_true
    APRV.apple_receipt_roots.each do |root|
      assert_equal root.subject.to_der, root.issuer.to_der
      assert APRV::Chain.ca?(root), "#{root.subject} is not a CA"
    end
  end

  # An anchor is trusted by fiat, so its expiry is never examined — but these
  # ones should also simply not be expired, and a surprise here is worth a
  # loud failure rather than a silent one.
  def test_the_bundled_roots_are_not_expired
    APRV.apple_receipt_roots.each do |root|
      assert_operator root.not_after, :>, Time.now, "#{root.subject} has expired"
    end
  end
end
