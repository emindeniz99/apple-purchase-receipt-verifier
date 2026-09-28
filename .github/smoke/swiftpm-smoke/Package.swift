// swift-tools-version: 6.0
//
// Smoke-tests the Swift library as SwiftPM consumers get it: resolved from the
// published git tag, not from this working tree. Run with the released version:
//
//   SMOKE_VERSION=0.7.0 swift run Smoke
//
// SwiftPM has no registry here, so the tag itself is the artifact — a tag whose
// Package.swift references files that were not committed fails at resolve time,
// which is exactly what this catches.
//
// Before a release, ci.yml's smoke-swiftpm job runs the same program against
// the checkout instead, so a broken smoke shows up on the pull request rather
// than after the tag is pushed:
//
//   SMOKE_PATH=<repo> swift run Smoke
import Foundation
import PackageDescription

let environment = ProcessInfo.processInfo.environment
let library: Package.Dependency
if let path = environment["SMOKE_PATH"] {
    // `name:` pins the identity the product lookup below matches, whatever
    // the directory the repository is checked out into is called.
    library = .package(name: "apple-purchase-receipt-verifier", path: path)
} else if let smokeVersion = environment["SMOKE_VERSION"] {
    library = .package(
        url: "https://github.com/emindeniz99/apple-purchase-receipt-verifier.git",
        exact: Version(stringLiteral: smokeVersion))
} else {
    fatalError("set SMOKE_VERSION to the published version, e.g. SMOKE_VERSION=0.7.0")
}

let package = Package(
    name: "Smoke",
    platforms: [
        .macOS(.v13),
    ],
    dependencies: [library],
    targets: [
        .executableTarget(
            name: "Smoke",
            dependencies: [
                .product(name: "ApplePurchaseReceiptVerifier",
                         package: "apple-purchase-receipt-verifier"),
            ]),
    ]
)
