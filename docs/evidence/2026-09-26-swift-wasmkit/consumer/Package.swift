// swift-tools-version:6.3
// Spike only (2026-09-26). A clean consumer: depends on the AprvWasm
// package by path (scripts/build.sh fills in @PKG@) and resolves WasmKit on
// its own. Nothing else.
import PackageDescription

let package = Package(
    name: "Consumer",
    platforms: [.macOS(.v15)],
    dependencies: [.package(path: "@PKG@")],
    targets: [.executableTarget(name: "Consumer", dependencies: [.product(name: "AprvWasm", package: "AprvWasm")])]
)
