// swift-tools-version:6.3
// At the repository root because SwiftPM resolves a package's manifest
// only from the root of the cloned repo (PLAN D6) — the Swift sources
// themselves stay under swift/.
//
// The library runs aprv.wasm, the one verification module every port of
// this repository shares, on WasmKit, an interpreter written in Swift. It
// holds no verification logic and no cryptography of its own
// (docs/rust-core/ARCHITECTURE.md §7.5). WasmKit declares tools 6.3,
// macOS 15 and iOS 18, which are therefore this package's floors
// (docs/rust-core/DECISIONS.md R30).
import PackageDescription

let package = Package(
    name: "apple-purchase-receipt-verifier",
    platforms: [
        .macOS(.v15), .iOS(.v18),  // and Linux server environments
    ],
    products: [
        .library(name: "ApplePurchaseReceiptVerifier", targets: ["ApplePurchaseReceiptVerifier"]),
    ],
    dependencies: [
        // 0.4.1 is the floor, not 0.4.0: 0.4.0's interpreter kept its cached
        // memory base across a host call, so a host function that re-enters
        // the guest and grows its memory left the next load reading freed
        // memory under software bounds checking. random-get is exactly that
        // host function (it allocates through the guest's cabi_realloc), and
        // software bounds checking is what AprvModule.configuration asks for.
        // 0.4.1 also stops a module from aborting the host with an allocation
        // it cannot satisfy.
        //
        // Only the MultiThread trait: every Verifier shares one Engine and
        // one Module across threads. FileSystem and Disassembler (the other
        // default traits) add code this package never calls: the module is
        // parsed from bytes, and nothing is disassembled.
        .package(url: "https://github.com/swiftwasm/WasmKit.git", from: "0.4.1", traits: ["MultiThread"]),
    ],
    targets: [
        .target(
            name: "ApplePurchaseReceiptVerifier",
            dependencies: [
                .product(name: "WasmKit", package: "WasmKit"),
            ],
            path: "swift/Sources/ApplePurchaseReceiptVerifier",
            resources: [
                .copy("Resources/aprv.wasm"),
                .copy("Resources/aprv.wasm.sha256"),
                // The licences of the code compiled into aprv.wasm (OpenSSL,
                // wasi-libc with musl, the Rust standard library), carried
                // wherever the module goes.
                .copy("Resources/licenses"),
            ]),
        .testTarget(
            name: "ApplePurchaseReceiptVerifierTests",
            dependencies: ["ApplePurchaseReceiptVerifier", .product(name: "WasmKit", package: "WasmKit")],
            path: "swift/Tests/ApplePurchaseReceiptVerifierTests",
            exclude: ["Resources/double.wat"],
            resources: [.copy("Resources/double.wasm")]),
    ]
)
