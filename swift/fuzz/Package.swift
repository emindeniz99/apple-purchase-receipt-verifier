// swift-tools-version: 6.1
// A package of its own, not targets in the root manifest: the published
// package's manifest is its public surface, and five libFuzzer executables
// no consumer can run would sit in it forever (fuzz/README.md, "Why a
// separate package"). It depends on the library by path, which is why the
// root manifest is untouched by this directory.
import PackageDescription

// Applied to every target, dependencies included: coverage instrumentation
// has to reach swift-asn1 and swift-certificates for the fuzzer to steer
// into them, and `-enable-testing` is what lets FuzzSupport reach the
// library's internal readers (`decodeReceiptBase64`, `base64URLDecode`)
// that no public entry point exposes on their own. The flags are passed on
// the command line by run.sh rather than pinned here so the sanitizer set
// stays switchable (`fuzzer` vs `fuzzer,address`) without editing this file.
let package = Package(
    name: "apple-purchase-receipt-verifier-fuzz",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(path: "../.."),
        // The splice in FuzzSupport needs a BER reader to find the payload
        // node it replaces. Same version range as the root manifest, so
        // SwiftPM resolves one copy for both packages.
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.2.0"),
    ],
    targets: [
        .target(
            name: "FuzzSupport",
            dependencies: [
                .product(
                    name: "ApplePurchaseReceiptVerifier",
                    package: "apple-purchase-receipt-verifier"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ]),
        .executableTarget(name: "receipt-der", dependencies: ["FuzzSupport"]),
        .executableTarget(name: "receipt-base64", dependencies: ["FuzzSupport"]),
        .executableTarget(name: "jws", dependencies: ["FuzzSupport"]),
        .executableTarget(name: "endpoint-json", dependencies: ["FuzzSupport"]),
        .executableTarget(name: "receipt-payload", dependencies: ["FuzzSupport"]),
        .executableTarget(name: "readers", dependencies: ["FuzzSupport"]),
    ]
)
