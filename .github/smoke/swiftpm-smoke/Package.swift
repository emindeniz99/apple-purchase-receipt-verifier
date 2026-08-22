// swift-tools-version: 6.0
//
// Smoke-tests the Swift library as SwiftPM consumers get it: resolved from the
// published git tag, not from this working tree. Run with the released version:
//
//   SMOKE_VERSION=0.2.1 swift run Smoke
//
// SwiftPM has no registry here, so the tag itself is the artifact — a tag whose
// Package.swift references files that were not committed fails at resolve time,
// which is exactly what this catches.
import Foundation
import PackageDescription

guard let smokeVersion = ProcessInfo.processInfo.environment["SMOKE_VERSION"] else {
    fatalError("set SMOKE_VERSION to the published version, e.g. SMOKE_VERSION=0.2.1")
}

let package = Package(
    name: "Smoke",
    platforms: [
        .macOS(.v13),
    ],
    dependencies: [
        .package(
            url: "https://github.com/emindeniz99/apple-purchase-receipt-verifier.git",
            exact: Version(stringLiteral: smokeVersion)),
    ],
    targets: [
        .executableTarget(
            name: "Smoke",
            dependencies: [
                .product(name: "ApplePurchaseReceiptVerifier",
                         package: "apple-purchase-receipt-verifier"),
            ]),
    ]
)
