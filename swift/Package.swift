// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ApplePurchaseVerifier",
    platforms: [
        .macOS(.v13), // and Linux server environments
    ],
    products: [
        .library(name: "ApplePurchaseVerifier", targets: ["ApplePurchaseVerifier"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.2.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0" ..< "4.0.0"),
    ],
    targets: [
        .target(
            name: "ApplePurchaseVerifier",
            dependencies: [
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ],
            resources: [.copy("certs")]),
        .testTarget(
            name: "ApplePurchaseVerifierTests",
            dependencies: ["ApplePurchaseVerifier"]),
    ]
)
