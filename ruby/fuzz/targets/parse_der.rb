# frozen_string_literal: true

# The bounded ASN.1 reader, on its own. Every other target reaches it through
# a structure walk; this one hands it arbitrary bytes so a length or depth bug
# shows up without a CMS or certificate shape around it.
#
# The invariant is the module's own documented contract: one well-formed value
# or an Asn1::Error. A SystemStackError here would mean the iterative scanner
# had grown a recursive path again, which is the exact regression
# Asn1.scan! exists to prevent.

require "ruzzy"
require_relative "../support"

APRV = FuzzSupport::APRV

TEST_ONE_INPUT = lambda do |data|
  outcome, = FuzzSupport.call("Asn1.scan!", APRV::Asn1::Error) { APRV::Asn1.scan!(data) }
  # The tree builder only ever runs on bytes the scanner passed, so that is
  # the only shape it is fuzzed in.
  FuzzSupport.call("Asn1.parse", APRV::Asn1::Error) { APRV::Asn1.parse(data) } if outcome == :accepted
  nil
end

Ruzzy.fuzz(TEST_ONE_INPUT)
