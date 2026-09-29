// swift-tools-version:6.3
// A package of its own, not targets in the root manifest: the published
// package's manifest is its public surface, and five libFuzzer executables
// no consumer can run would sit in it forever (fuzz/README.md, "Why a
// separate package"). It depends on the library by path, which is why the
// root manifest is untouched by this directory.
import PackageDescription

// Applied to every target, dependencies included: coverage instrumentation
// has to reach WasmKit, the interpreter the library runs aprv.wasm on, for
// the fuzzer to steer into it and into the host glue around it. The flags are
// passed on the command line by run.sh rather than pinned here so the
// sanitizer set stays switchable (`fuzzer` vs `fuzzer,address`) without
// editing this file.
let package = Package(
    name: "apple-purchase-receipt-verifier-fuzz",
    platforms: [.macOS(.v15), .iOS(.v18)],
    dependencies: [
        // `name:` is what the product lookup below matches. Without it the
        // identity comes from the directory the library sits in, and
        // Dependabot checks the repository out as "repo", so its weekly
        // swift/fuzz run died on an unknown package (2026-09-19).
        .package(name: "apple-purchase-receipt-verifier", path: "../.."),
    ],
    targets: [
        .target(
            name: "FuzzSupport",
            dependencies: [
                .product(
                    name: "ApplePurchaseReceiptVerifier",
                    package: "apple-purchase-receipt-verifier")
            ]),
        .executableTarget(name: "receipt-der", dependencies: ["FuzzSupport"]),
        .executableTarget(name: "receipt-base64", dependencies: ["FuzzSupport"]),
        .executableTarget(name: "jws", dependencies: ["FuzzSupport"]),
        .executableTarget(name: "endpoint-json", dependencies: ["FuzzSupport"]),
    ]
)
