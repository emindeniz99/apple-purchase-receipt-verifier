# frozen_string_literal: true

require_relative "lib/apple_purchase_receipt_verifier/version"

Gem::Specification.new do |spec|
  spec.name = "apple-purchase-receipt-verifier"
  spec.version = ApplePurchaseReceiptVerifier::VERSION
  spec.authors = ["emindeniz99"]
  spec.license = "MIT"

  spec.summary = "Offline verification of Apple App Store purchase receipts " \
                 "(StoreKit 2 JWS and legacy PKCS#7)"
  spec.description = <<~TEXT
    Verifies Apple App Store purchase receipts on your own servers, with no call
    to Apple: StoreKit 2 / App Store Server JWS payloads and legacy PKCS#7 app
    receipts, against pinned Apple root certificates. Includes a drop-in local
    replacement for the deprecated verifyReceipt endpoint. The verification
    runs in one WebAssembly module, shared with this project's other language
    packages, on the wasmtime gem: no network access, no operating-system trust
    store, no native code of ours.
  TEXT
  spec.homepage = "https://github.com/emindeniz99/apple-purchase-receipt-verifier"

  spec.metadata = {
    "homepage_uri" => spec.homepage,
    "source_code_uri" => spec.homepage,
    "changelog_uri" => "#{spec.homepage}/blob/main/CHANGELOG.md",
    "bug_tracker_uri" => "#{spec.homepage}/issues",
    "rubygems_mfa_required" => "true"
  }

  # 0.7 API floor (docs/design/0.7-api.md, per-port table): `Data.define`
  # value classes need Ruby 3.2+; 3.3 is the tested floor, up from 0.6's 3.1.
  spec.required_ruby_version = ">= 3.3.0"

  # lib/ holds the WebAssembly module and the SHA-256 the gem checks it
  # against; licenses/ holds the texts its third-party code requires. Not
  # shipped: roots_data.rb (Apple's roots live inside the module now, and the
  # file only waits for the release that deletes it), certs/, and the tests.
  #
  # The module is not tracked in git: the release job copies it to the path
  # below before `gem build`, and a build without it stops here.
  module_file = File.join(__dir__, "lib/apple_purchase_receipt_verifier/aprv.wasm")
  unless File.file?(module_file)
    raise "lib/apple_purchase_receipt_verifier/aprv.wasm is missing: copy the release " \
          "build of the module there before `gem build`"
  end

  spec.files = Dir[
    "lib/**/*.rb",
    "lib/**/aprv.wasm",
    "lib/**/aprv.wasm.sha256",
    "sig/**/*.rbs",
    "licenses/**/*",
    "README.md",
    "LICENSE"
  ] - ["lib/apple_purchase_receipt_verifier/roots_data.rb"]
  spec.require_paths = ["lib"]

  # The one runtime dependency: Bytecode Alliance's Wasmtime, whose prebuilt
  # native gems (Linux glibc and musl, macOS, Windows; Ruby 3.3 and later)
  # install without a Rust toolchain. 48.0.1 is the release the module was
  # measured on; it has `Extern#to_func(gvl: false)`, which lets threads
  # verify in parallel.
  spec.add_dependency "wasmtime", ">= 48.0.1"
end
