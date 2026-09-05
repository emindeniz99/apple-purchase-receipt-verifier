# frozen_string_literal: true

# The CMS SignedData walk, in the composition Receipt.verify uses it in:
# Asn1.scan! first, then Cms.parse on bytes already proven shallow and fully
# consumed. This is the walk a pre-port probe found an out-of-bounds read in
# by mutating a genuine receipt, so it gets its own target rather than only
# being reached through verify_receipt.
#
# Invariant: after a scan that passed, the only error Cms.parse may raise is a
# VerificationError, and every accessor on what it returns must be readable.

require "ruzzy"
require_relative "../support"

APRV = FuzzSupport::APRV

TEST_ONE_INPUT = lambda do |data|
  scanned, = FuzzSupport.call("Asn1.scan!", APRV::Asn1::Error) { APRV::Asn1.scan!(data) }
  next nil unless scanned == :accepted

  parsed_outcome, parsed = FuzzSupport.call("Cms.parse", APRV::VerificationError) { APRV::Cms.parse(data) }
  next nil unless parsed_outcome == :accepted

  FuzzSupport.call("Cms::Parsed accessors", APRV::VerificationError) do
    parsed.content&.bytesize
    parsed.certificate_ders.each(&:bytesize)
    info = parsed.signer_info
    [info.issuer_der&.bytesize, info.serial, info.digest_oid, info.digest_name]
  end
  nil
end

Ruzzy.fuzz(TEST_ONE_INPUT)
