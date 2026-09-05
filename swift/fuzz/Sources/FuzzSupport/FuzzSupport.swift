import Foundation
import SwiftASN1

// `@testable` rather than a plain import: `decodeReceiptBase64` and
// `base64URLDecode` are internal, and they are two of the three hand-written
// readers this port owns. Reaching them only through a verifier would mean
// fuzzing them behind a chain build, which is thousands of times slower per
// execution and hides which layer rejected an input. Everything internal is
// touched here and re-exported as the `Readers` shims below, so exactly one
// file in this package depends on `-enable-testing`.
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

    public static func load(_ components: String...) -> Data {
        let url = components.reduce(directory) { $0.appendingPathComponent($1) }
        guard let data = try? Data(contentsOf: url) else {
            // Not a finding: the harness could not start. Said plainly so it
            // is not mistaken for a crasher the fuzzer reduced.
            fatalError(
                "fuzz harness setup failed: no fixture at \(url.path) — "
                    + "set APRV_FIXTURES to the repository's fixtures/ directory")
        }
        return data
    }

    /// The generated PKI's receipt root: the anchor that lets the fixture
    /// receipts past the chain check, so a fuzzer can explore what lies
    /// beyond it instead of stopping at every chain build.
    public static let receiptRoot = load("generated", "receipt-root.der")
    /// The generated PKI's JWS root — the *unrelated* anchor set for the
    /// receipt targets, and the trusted one for the JWS target.
    public static let jwsRoot = load("generated", "jws-root.der")

    /// The bundle id and environment every generated fixture carries
    /// (fixtures/generated/manifest.json).
    public static let bundleId = "com.example.app"
}

// MARK: - Running an async entry point from libFuzzer

/// libFuzzer calls `LLVMFuzzerTestOneInput` on its own thread and expects it
/// to return; every verification entry point in this library is `async`
/// because chain building is. Blocking that one thread on a semaphore is the
/// bridge — the task runs on the cooperative pool's own threads, so nothing
/// the fuzzer thread waits for is scheduled on the fuzzer thread.
private final class Box<T>: @unchecked Sendable {
    var result: Result<T, any Error>?
}

public func blocking<T: Sendable>(_ body: @escaping @Sendable () async throws -> T) throws -> T {
    let box = Box<T>()
    let done = DispatchSemaphore(value: 0)
    Task.detached {
        do {
            box.result = .success(try await body())
        } catch {
            box.result = .failure(error)
        }
        done.signal()
    }
    done.wait()
    return try box.result!.get()
}

// MARK: - Invariants

/// Every failure this library reports must be its own typed error. Anything
/// else — a Foundation error leaking out of a decoder, a `CocoaError` from a
/// formatter — is a finding, because a caller that catches
/// `VerificationError` would not catch it and the payload would be treated
/// as something other than untrusted.
public func requireTypedError(
    _ error: any Error, _ what: String, file: StaticString = #filePath, line: UInt = #line
) -> Never? {
    if error is VerificationError { return nil }
    fail("\(what) failed with \(type(of: error)) instead of VerificationError: \(error)")
}

public func fail(_ message: String) -> Never {
    // fatalError, not a thrown error: libFuzzer only records a unit as a
    // crasher when the process dies, so an invariant that merely returned
    // would be silently forgotten by the next execution.
    FileHandle.standardError.write(Data("fuzz invariant violated: \(message)\n".utf8))
    fatalError("fuzz invariant violated: \(message)")
}

// MARK: - The library's hand-written readers, re-exported

/// The three readers this port writes by hand, exposed so the `readers`
/// target can drive them directly rather than through a verifier.
public enum Readers {
    /// The receipt base64 rule: whitespace-tolerant, one alphabet at a time,
    /// padding validated in place.
    public static func decodeReceiptBase64(_ text: String) -> Data? {
        ApplePurchaseReceiptVerifier.decodeReceiptBase64(text)
    }

    /// Strict unpadded canonical base64url — the compact-JWS segment rule.
    public static func base64URLDecode(_ segment: String) -> Data? {
        ApplePurchaseReceiptVerifier.base64URLDecode(segment)
    }

    /// The GeneralizedTime-representable window a date must be inside before
    /// it is allowed to reach a certificate policy.
    public static func isRepresentableAsCertificateValidationTime(_ date: Date) -> Bool {
        ApplePurchaseReceiptVerifier.isRepresentableAsCertificateValidationTime(date)
    }
}

// MARK: - Receipt payload surgery

/// Splices arbitrary bytes in as a genuine receipt's payload, so the
/// attribute-SET walk and the string/integer/date decoders under it can be
/// fuzzed on raw input.
///
/// They are reachable no other way: `parseAttributeSet`, `decodeString`,
/// `decodeInteger` and `decodeDate` are file-private inside
/// ReceiptVerifier.swift, so not even `@testable` reaches them. What makes
/// the splice work is the order of `verifyCore`: the payload is parsed
/// *before* the chain and signature checks, deliberately, because the chain
/// is judged at the receipt's creation date. A spliced receipt can therefore
/// never verify — the CMS messageDigest no longer matches — but everything
/// the parser decides happens first, on bytes the fuzzer chose.
///
/// The fixtures are BER with indefinite lengths from the CMS SEQUENCE down
/// to that OCTET STRING, so replacing the one primitive node needs no
/// ancestor length fixups. This is the same property
/// `PortDivergenceTests.ReceiptSurgery` relies on.
public struct PayloadSplice: Sendable {
    private let prefix: [UInt8]
    private let suffix: [UInt8]

    public init(template: Data) {
        let bytes = [UInt8](template)
        guard let node = try? Self.payloadNode(bytes) else {
            fatalError("fuzz harness setup failed: the receipt template has no payload OCTET STRING")
        }
        let range = node.encodedBytes
        self.prefix = Array(bytes[..<range.startIndex])
        self.suffix = Array(bytes[range.endIndex...])
    }

    /// The template receipt with `payload` as its attribute set.
    public func receipt(payload: [UInt8]) -> Data {
        Data(prefix + Self.octetString(payload) + suffix)
    }

    /// contentInfo → [0] → SignedData → encapContentInfo → [0] → OCTET STRING.
    private static func payloadNode(_ receipt: [UInt8]) throws -> ASN1Node {
        let contentInfo = try children(BER.parse(receipt))
        let signedData = try children(children(contentInfo[1])[0])
        let encap = try children(signedData[2])
        return try children(children(encap[1])[0])[0]
    }

    private static func children(_ node: ASN1Node) throws -> [ASN1Node] {
        guard case .constructed(let nodes) = node.content else {
            throw ASN1Error.invalidASN1Object(reason: "expected a constructed node")
        }
        return Array(nodes)
    }

    /// A definite-length DER OCTET STRING around `content`. Hand-rolled
    /// rather than serialized: the length must be encoded for a payload of
    /// any size the fuzzer produces, and that is the whole of it.
    private static func octetString(_ content: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [0x04]
        if content.count < 0x80 {
            out.append(UInt8(content.count))
        } else {
            var length: [UInt8] = []
            var remaining = content.count
            while remaining > 0 {
                length.insert(UInt8(remaining & 0xFF), at: 0)
                remaining >>= 8
            }
            out.append(0x80 | UInt8(length.count))
            out.append(contentsOf: length)
        }
        out.append(contentsOf: content)
        return out
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
