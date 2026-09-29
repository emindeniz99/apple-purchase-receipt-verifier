// swift-tools-version:6.3
// Spike only (2026-09-29, round 13). The canonical-ABI aprv module on
// WasmKit 0.4.0 (the Swift interpreter; round 7's version), called by hand:
// no component runtime, no generated bindings. The module is read from a
// file given on the command line; nothing is bundled.
import PackageDescription

let package = Package(
    name: "AprvCabi",
    platforms: [.macOS(.v15), .iOS(.v18)],
    dependencies: [
        .package(url: "https://github.com/swiftwasm/WasmKit.git", exact: "0.4.0"),
    ],
    targets: [
        // Swift 5 language mode: a throwaway harness with a global test hook.
        .executableTarget(name: "aprv-cabi", dependencies: [.product(name: "WasmKit", package: "WasmKit")],
                          swiftSettings: [.swiftLanguageMode(.v5)]),
    ]
)
