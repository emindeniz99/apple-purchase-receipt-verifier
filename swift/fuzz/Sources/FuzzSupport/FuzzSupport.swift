import Foundation

// `@testable` rather than a plain import: `decodeReceiptBase64`,
// `decodeBase64URLStrict` and the receipt payload parser are internal, and
// they are the readers this port writes by hand. Reaching them only through
// a verifier would mean fuzzing them behind a chain build, which is
// thousands of times slower per execution and hides which layer rejected an
// input. Everything internal is touched here and re-exported as the shims
// below, so exactly one file in this package depends on `-enable-testing`.
@testable import ApplePurchaseReceiptVerifier

// MARK: - Fixtures

/// The shared fixture tree, read in place. Nothing under `fixtures/` is
/// copied into this directory: the seeds a run uses are the real files, and
/// the two anchors below are loaded from them at startup.
public enum Fixtures {
    /// `$APRV_FIXTURES` when set (run.sh sets it), else `fixtures/` five
    /// levels above this file: Sources/FuzzSupport → Sources → fuzz → swift
    /// → the repository root.
    public static let directory: URL = {
        if let override = ProcessInfo.processInfo.environment["APRV_FIXTURES"], !override.isEmpty {
            return URL(fileURLWithPath: override)
        }
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { url = url.deletingLastPathComponent() }
        return url.appendingPathComponent("fixtures")
    }()

    public static func load(_ components: String...) -> [UInt8] {
        let url = components.reduce(directory) { $0.appendingPathComponent($1) }
        guard let data = try? Data(contentsOf: url) else {
            // Not a finding: the harness could not start. Said plainly so it
            // is not mistaken for a crasher the fuzzer reduced.
            fatalError(
                "fuzz harness setup failed: no fixture at \(url.path) — "
                    + "set APRV_FIXTURES to the repository's fixtures/ directory")
        }
        return [UInt8](data)
    }

    /// The 0.7 generated PKI's receipt root: the anchor that lets the fixture
    /// receipts past the chain check, so a fuzzer can explore what lies
    /// beyond it instead of stopping at every chain build. The 0.6 receipts
    /// under `generated/` lack the WWDR marker on their intermediate, which
    /// 0.7 requires, so they stop at the marker check.
    public static let receiptRoot = load("generated-0.7", "receipt-root.der")
    /// The generated PKI's JWS root — the *unrelated* anchor set for the
    /// receipt targets, and the trusted one for the JWS target.
    public static let jwsRoot = load("generated", "jws-root.der")

    /// A verifier over `roots` and the system clock, or a setup failure.
    public static func verifier(roots: [[UInt8]], what: String) -> Verifier {
        guard let config = try? Config.builder().roots(roots).build() else {
            fatalError("fuzz harness setup failed: the \(what) anchor set is not loadable")
        }
        return Verifier(config: config)
    }

    /// Apple's three pinned roots, as DER, from the repository's `certs/`
    /// (the directory next to `fixtures/`), which the library's bundled copy
    /// is checked against.
    public static let appleRoots: [[UInt8]] = {
        let certs = directory.deletingLastPathComponent().appendingPathComponent("certs")
        return ["AppleIncRootCertificate.cer", "AppleRootCA-G2.cer", "AppleRootCA-G3.cer"].map { name in
            guard let data = try? Data(contentsOf: certs.appendingPathComponent(name)) else {
                fatalError("fuzz harness setup failed: no Apple root at \(certs.path)/\(name)")
            }
            return [UInt8](data)
        }
    }()
}

// MARK: - Invariants

/// 0.7's verify methods never throw; what a fuzzer can still catch is the
/// wrong verdict class. `INTERNAL_ERROR` means the library itself broke, and
/// the design allows input to reach it only through a missing trust anchor,
/// which no target here configures — so any input that produces it is a
/// finding: an attacker who can send bytes could raise the internal-error
/// alarm at will.
public func requireNoInternalError<T>(
    _ result: VerificationResult<T>, _ what: String
) {
    if result.failure?.reason == .internalError {
        fail("\(what) answered INTERNAL_ERROR: \(result.failure!.message)")
    }
    if (result.payload == nil) == (result.failure == nil) {
        fail("\(what) returned neither or both of a payload and a failure")
    }
}

public func fail(_ message: String) -> Never {
    // fatalError, not a thrown error: libFuzzer only records a unit as a
    // crasher when the process dies, so an invariant that merely returned
    // would be silently forgotten by the next execution.
    FileHandle.standardError.write(Data("fuzz invariant violated: \(message)\n".utf8))
    fatalError("fuzz invariant violated: \(message)")
}

// MARK: - The library's hand-written readers, re-exported

/// The readers this port writes by hand, exposed so the `readers` and
/// `receipt-payload` targets can drive them directly rather than through a
/// verifier.
public enum Readers {
    /// The receipt base64 rule: canonical standard base64 and nothing else.
    public static func decodeReceiptBase64(_ text: String) -> [UInt8]? {
        ApplePurchaseReceiptVerifier.decodeReceiptBase64(text)
    }

    /// Strict unpadded canonical base64url — the compact-JWS segment rule.
    public static func base64URLDecode(_ segment: String) -> [UInt8]? {
        ApplePurchaseReceiptVerifier.decodeBase64URLStrict(segment)
    }

    /// The full payload parse, as it runs after a signature has verified:
    /// the payload, or the error that becomes `UNREADABLE_PAYLOAD`'s cause.
    public static func parseReceiptPayload(_ content: [UInt8]) -> Result<ReceiptPayload, any Error> {
        Result { try ApplePurchaseReceiptVerifier.parseReceiptPayload(content) }
    }

    /// Whether `error` is the payload parser's own error type, the one the
    /// verifier hands a caller as the cause.
    public static func isPayloadError(_ error: any Error) -> Bool { error is PayloadError }

    /// The unverified read of attribute 12 that picks the chain instant.
    public static func readCreationDate(_ content: [UInt8]) -> Int64? {
        ApplePurchaseReceiptVerifier.readCreationDate(content)
    }
}

// MARK: - libFuzzer input

/// The bytes of one libFuzzer execution.
public func fuzzInput(_ start: UnsafeRawPointer, _ count: Int) -> [UInt8] {
    [UInt8](UnsafeRawBufferPointer(start: start, count: count))
}

/// The same bytes as a `String`, or `nil` when they are not UTF-8. The three
/// string-taking entry points are `String`-typed, so non-UTF-8 input cannot
/// reach them and is skipped rather than lossily repaired — repairing it
/// would fuzz the repair, not the library.
public func fuzzText(_ start: UnsafeRawPointer, _ count: Int) -> String? {
    String(bytes: UnsafeRawBufferPointer(start: start, count: count), encoding: .utf8)
}

// MARK: - Starting libFuzzer

/// libFuzzer's own `main` cannot be the one that runs. SwiftPM builds a
/// Linux executable target by aliasing `main` to the module's entry point
/// (`ld --defsym main=<module>_main`), so a target compiled
/// `-parse-as-library` — the usual way to let libFuzzer's `main` link —
/// leaves that alias pointing at nothing and the link fails with
/// `undefined symbol '<module>_main'`.
///
/// So each target keeps an ordinary `main.swift` and calls libFuzzer's
/// driver from it. `LLVMFuzzerRunDriver` is the same driver `main` calls,
/// takes the same argv, and lives in a different object file inside
/// libclang_rt.fuzzer, so the member defining `main` is never pulled in and
/// nothing collides.
public typealias FuzzTestOneInput = @convention(c) (UnsafePointer<UInt8>?, Int) -> CInt

@_silgen_name("LLVMFuzzerRunDriver")
private func llvmFuzzerRunDriver(
    _ argc: UnsafeMutablePointer<CInt>,
    _ argv: UnsafeMutablePointer<UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>>,
    _ callback: FuzzTestOneInput
) -> CInt

/// Hands control to libFuzzer, which parses the corpus directories and
/// flags out of the process arguments and never returns.
public func runFuzzer(_ callback: FuzzTestOneInput) -> Never {
    var argc = CommandLine.argc
    var argv = CommandLine.unsafeArgv
    exit(llvmFuzzerRunDriver(&argc, &argv, callback))
}
