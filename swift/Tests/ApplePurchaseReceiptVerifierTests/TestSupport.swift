import Foundation
import XCTest

@testable import ApplePurchaseReceiptVerifier

/// The fixture tree and the verifiers the tests build from it.
enum TestFixtures {
    static var directory: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // ApplePurchaseReceiptVerifierTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // swift
            .deletingLastPathComponent()  // project root
            .appendingPathComponent("fixtures")
    }

    static func bytes(_ path: String) throws -> [UInt8] {
        [UInt8](try Data(contentsOf: directory.appendingPathComponent(path)))
    }

    /// A text fixture without its trailing newline.
    static func text(_ path: String) throws -> String {
        String(decoding: try Data(contentsOf: directory.appendingPathComponent(path)), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// A verifier anchored on the DER fixtures at `roots`, reading a fixed
    /// clock when one is given.
    static func verifier(roots: [String], clock: Int64? = nil) throws -> ApplePurchaseReceiptVerifier.Verifier {
        var builder = try Config.builder().roots(roots.map { try bytes($0) })
        if let clock { builder = builder.clock { clock } }
        return ApplePurchaseReceiptVerifier.Verifier(config: try builder.build())
    }

    /// The generated 0.7 receipt and the root that anchors it.
    static let receipt = "generated-0.7/receipt.der"
    static let receiptRoot = "generated-0.7/receipt-root.der"
    static let jws = "generated/transaction.jws"
    static let jwsRoot = "generated/jws-root.der"
    static let g5 = "public-receipts/receipt-sandbox-g5.b64"

    /// The `status` of an endpoint response, read as a value: key order in
    /// the response is free.
    static func status(_ response: String) -> Int? {
        (try? JSONSerialization.jsonObject(with: Data(response.utf8)) as? [String: Any])?["status"] as? Int
    }

    /// The test double of the ABI (Resources/double.wat).
    static func double() throws -> AprvModule {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "double", withExtension: "wasm"))
        return try AprvModule.load([UInt8](try Data(contentsOf: url)))
    }
}

/// Padded standard base64, the receipt-data form.
func standardBase64Encode(_ bytes: [UInt8]) -> String { Data(bytes).base64EncodedString() }

/// Unpadded base64url, the compact-JWS segment form.
func base64URL(_ bytes: [UInt8]) -> String {
    standardBase64Encode(bytes)
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

/// The inverse of ``base64URL(_:)`` for well-formed test input.
func base64URLDecode(_ segment: String) -> [UInt8]? {
    var text = segment.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while text.count % 4 != 0 { text += "=" }
    return Data(base64Encoded: text).map { [UInt8]($0) }
}

/// `object` as compact JSON text.
func jsonText(_ object: [String: Any]) -> String {
    String(decoding: try! JSONSerialization.data(withJSONObject: object, options: [.withoutEscapingSlashes]), as: UTF8.self)
}

/// A seeded generator, so a failing input can be reproduced. The standard
/// library's `SystemRandomNumberGenerator` cannot be seeded.
struct SplitMix64: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        state = seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

/// A clock that counts its reads.
final class CountingClock: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    private let now: Int64
    init(_ now: Int64) { self.now = now }

    var reads: Int {
        lock.lock()
        defer { lock.unlock() }
        return count
    }

    var read: @Sendable () -> Int64 {
        { [self] in
            lock.lock()
            defer { lock.unlock() }
            count += 1
            return now
        }
    }
}
