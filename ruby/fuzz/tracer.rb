# frozen_string_literal: true

# The entry point every run goes through. Ruzzy turns on Ruby's branch
# coverage and *then* requires the target, so the target — and everything it
# requires, the library included — is compiled with the instrumentation
# libFuzzer steers by. Requiring a target directly instead of through here
# fuzzes with no coverage feedback at all.
#
# The target comes from the environment, not from ARGV, because ARGV belongs
# to libFuzzer (corpus directories and -flags).
require "ruzzy"

name = ENV.fetch("APRV_FUZZ_TARGET", nil)
raise "set APRV_FUZZ_TARGET to a target name, e.g. parse_der" if name.nil? || name.empty?

path = File.expand_path("targets/#{name}.rb", __dir__)
raise "no such fuzz target: #{name} (expected #{path})" unless File.file?(path)

Ruzzy.trace(path)
