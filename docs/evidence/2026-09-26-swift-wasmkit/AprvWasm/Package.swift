// swift-tools-version:6.3
// Spike only (2026-09-26). aprv.wasm (ABI v1) on WasmKit, the Swift
// interpreter from swiftwasm. The module file is copied into
// Sources/AprvWasm/Resources/ by scripts/build.sh; it is not in the
// repository.
import PackageDescription

let package = Package(
    name: "AprvWasm",
    platforms: [.macOS(.v15), .iOS(.v18)],
    products: [
        .library(name: "AprvWasm", targets: ["AprvWasm"]),
    ],
    dependencies: [
        .package(url: "https://github.com/swiftwasm/WasmKit.git", exact: "0.4.0"),
    ],
    targets: [
        .target(
            name: "AprvWasm",
            dependencies: [.product(name: "WasmKit", package: "WasmKit")],
            resources: [.copy("Resources/aprv.wasm")]
        ),
        // The spike's harness: ABI tests, corpus runner, benchmarks.
        // Swift 5 language mode: a throwaway harness with global counters.
        .executableTarget(name: "aprv-tool", dependencies: ["AprvWasm"], swiftSettings: [.swiftLanguageMode(.v5)]),
    ]
)
