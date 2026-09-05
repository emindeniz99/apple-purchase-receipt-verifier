# frozen_string_literal: true

# Writes the endpoint_json seed corpus into a scratch directory.
#
# The other five targets are seeded straight from fixtures/, which libFuzzer
# reads as extra read-only corpus directories. The endpoint takes a JSON
# request body, and no fixture is one, so its seeds have to be built —
# generated here at run time rather than committed, so a receipt fixture is
# never copied into this port's tree where it could drift from the shared one.
#
#   ruby seeds.rb <output directory>

require "json"
require_relative "support"

output = ARGV[0] or abort("usage: ruby seeds.rb <output directory>")
fixtures = FuzzSupport.fixtures_root
require "fileutils"
FileUtils.mkdir_p(output)

# Bodies that are not receipts at all: the shapes that exercise the JSON and
# receipt-data branches before a byte of DER is read.
{
  "null.json" => "null",
  "empty-object.json" => "{}",
  "not-json.json" => "not json at all",
  "empty-receipt-data.json" => JSON.generate({ "receipt-data" => "" }),
  "not-a-receipt.json" => JSON.generate({ "receipt-data" => "AAAA" }),
  "wrong-type.json" => JSON.generate({ "receipt-data" => 7 }),
  "with-password.json" => JSON.generate({ "receipt-data" => "AAAA", "password" => "x",
                                          "exclude-old-transactions" => true })
}.each { |name, body| File.binwrite(File.join(output, name), body) }

# And bodies that carry a receipt the verifier can get all the way through.
Dir[File.join(fixtures, "public-receipts", "*.b64"),
    File.join(fixtures, "generated", "receipt-b64", "*.txt")].sort.each do |path|
  name = "#{File.basename(File.dirname(path))}-#{File.basename(path, ".*")}.json"
  body = JSON.generate({ "receipt-data" => File.read(path).strip })
  File.binwrite(File.join(output, name), body)
end

puts "wrote #{Dir[File.join(output, "*.json")].length} endpoint_json seeds to #{output}"
