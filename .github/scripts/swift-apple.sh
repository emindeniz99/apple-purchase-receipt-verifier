#!/usr/bin/env bash
# The Swift package on Apple's platforms, as ci.yml runs it on macos-26:
#
#   .github/scripts/swift-apple.sh test   the suite on macOS (swift-macos)
#   .github/scripts/swift-apple.sh ios    the iOS 18 compile (swift-ios)
#
# Run from the repository root, after place-module put the module in the
# package. A push to main runs each in its own job; on a pull request
# swift-apple runs both on one runner. One script keeps the two from
# drifting.
set -euo pipefail

case "${1:-}" in
  test)
    swift --version
    swift test -c release -Xswiftc -enable-testing --force-resolved-versions
    ;;
  # The iOS 18 compile the manifest claims, which Linux cannot do: the
  # package and WasmKit build for a generic iOS device with the software
  # bounds checking the package selects there. Nothing runs on a device.
  ios)
    xcodebuild -version
    xcodebuild -list
    xcodebuild build -scheme apple-purchase-receipt-verifier \
      -destination 'generic/platform=iOS' -skipPackagePluginValidation
    ;;
  *)
    echo "usage: $0 test|ios" >&2
    exit 2
    ;;
esac
