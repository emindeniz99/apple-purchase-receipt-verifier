// swift-tools-version: 6.1
// The cross-port benchmark (BENCHMARKS.md at the repository root). A package
// of its own, like fuzz/, not a target in the root manifest: the published
// package's manifest is its public surface, and a benchmark executable no
// consumer runs would sit in it forever. It depends on the library by path,
// so the root manifest is untouched by this directory. Build it with
// `-c release`.
import PackageDescription

let package = Package(
    name: "apple-purchase-receipt-verifier-bench",
    platforms: [.macOS(.v13)],
    dependencies: [
        // `name:` is what the product lookup below matches, whatever the
        // directory the repository is checked out into is called.
        .package(name: "apple-purchase-receipt-verifier", path: "../..")
    ],
    targets: [
        .executableTarget(
            name: "bench",
            dependencies: [
                .product(
                    name: "ApplePurchaseReceiptVerifier",
                    package: "apple-purchase-receipt-verifier")
            ])
    ]
)
