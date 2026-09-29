# frozen_string_literal: true

# Spike only (2026-09-26). The facade gem: pure Ruby plus aprv.wasm (copied
# into lib/aprv_wasm/ by scripts/build.sh; not in the repository). All
# native code comes from the wasmtime gem on RubyGems.
Gem::Specification.new do |s|
  s.name = "aprv_wasm_spike"
  s.version = "0.0.0"
  s.summary = "Spike: apple-purchase-receipt-verifier's aprv.wasm on wasmtime-rb (ABI v1)"
  s.authors = ["spike"]
  s.license = "MIT"
  s.required_ruby_version = ">= 3.1"
  s.files = ["lib/aprv_wasm.rb", "lib/aprv_wasm/aprv.wasm"]
  s.add_dependency "wasmtime", "= 48.0.1"
end
