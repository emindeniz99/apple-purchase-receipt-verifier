// swift-tools-version: 6.0
// At the repository root because SwiftPM resolves a package's manifest
// only from the root of the cloned repo (PLAN D6) — the Swift sources
// themselves stay under swift/.
import PackageDescription

let package = Package(
    name: "apple-purchase-receipt-verifier",
    platforms: [
        .macOS(.v13), // and Linux server environments
    ],
    products: [
        .library(name: "ApplePurchaseReceiptVerifier", targets: ["ApplePurchaseReceiptVerifier"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.2.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0" ..< "4.0.0"),
    ],
    targets: [
        .target(
            name: "ApplePurchaseReceiptVerifier",
            dependencies: [
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ],
            path: "swift/Sources/ApplePurchaseReceiptVerifier",
            resources: [.copy("certs")]),
        .testTarget(
            name: "ApplePurchaseReceiptVerifierTests",
            dependencies: ["ApplePurchaseReceiptVerifier"],
            path: "swift/Tests/ApplePurchaseReceiptVerifierTests"),
    ]
)
