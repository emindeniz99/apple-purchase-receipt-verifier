import Foundation
import XCTest
@testable import ApplePurchaseReceiptVerifier

// Runs fixtures/cases.json — the normative cross-language conformance
// vectors — against this implementation. The adapter below knows nothing
// about any individual case: it loads the file, resolves fixture ids to
// bytes, builds a verifier from the generic config, dispatches on
// "operation", normalizes the result and reads the reason off a failure.
// A vector that disagrees with the library is a bug report against one of
// the two; it is never something to special-case here.

/// Anything wrong with the vectors, the fixtures or this adapter — never a
/// verdict about a payload. It is reported as a harness failure, and is
/// deliberately not a ``VerificationError``, so it can never be mistaken for
/// one of the canonical reasons a case expects.
private struct HarnessError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

/// fixtures/, four directories up from this file.
private let fixturesDirectory = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()  // ApplePurchaseReceiptVerifierTests
    .deletingLastPathComponent()  // Tests
    .deletingLastPathComponent()  // swift
    .deletingLastPathComponent()  // project root
    .appendingPathComponent("fixtures")

/// Nothing in this library takes a clock: ``JwsVerifier`` reads the system
/// clock directly for the max-signed-age check, so a case pinning "now"
/// cannot be run faithfully without adding a clock seam — a library change,
/// not a test change. Those cases are skipped and their ids printed.
private let noClockSeam = "no clock seam in swift: the library reads the system clock directly, "
    + "so a case pinning \"now\" cannot be run faithfully"

// verifyRaw enforces no claim, so its cases may omit bundleId and
// acceptedEnvironments — but the initializer still demands both. These
// placeholders match nothing the fixtures carry, so a claim check that leaked
// into verifyRaw would surface as a failure, not as a pass.
private let unmatchableBundleId = "conformance.unset.bundle.id"
private let unmatchableEnvironments: Set<AppleEnvironment> = [.localTesting]

// MARK: - the vector file

/// The parsed vector file plus the adapter that drives this library from it.
/// A value rather than a global: `[String: Any]` is not `Sendable`, and a
/// global of a non-Sendable type is rejected under the Swift 6 language mode
/// the package manifest selects.
private struct Vectors {
    let fixtures: [String: Any]
    let cases: [[String: Any]]

    init() throws {
        let data = try Data(contentsOf: fixturesDirectory.appendingPathComponent("cases.json"))
        guard let file = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let fixtures = file["fixtures"] as? [String: Any],
              let cases = file["cases"] as? [[String: Any]] else {
            throw HarnessError("fixtures/cases.json is not the expected JSON object")
        }
        self.fixtures = fixtures
        self.cases = cases
    }

    /// Decodes a registered fixture to its logical bytes (fixture.codec).
    func bytes(of id: String) throws -> Data {
        guard let entry = fixtures[id] as? [String: Any],
              let path = entry["path"] as? String,
              let codec = entry["codec"] as? String else {
            throw HarnessError("cases.json registers no fixture \"\(id)\"")
        }
        let raw = try Data(contentsOf: fixturesDirectory.appendingPathComponent(path))
        switch codec {
        case "raw":
            return raw
        case "base64":
            guard let text = String(data: raw, encoding: .utf8),
                  let decoded = Data(base64Encoded: text, options: [.ignoreUnknownCharacters]) else {
                throw HarnessError("fixture \"\(id)\" is not decodable base64")
            }
            return decoded
        case "utf8":
            guard let text = String(data: raw, encoding: .utf8) else {
                throw HarnessError("fixture \"\(id)\" is not valid UTF-8")
            }
            return Data(text.trimmingCharacters(in: .whitespacesAndNewlines).utf8)
        default:
            throw HarnessError("unknown fixture codec \"\(codec)\"")
        }
    }

    func trustedRoots(_ config: [String: Any]) throws -> [Data] {
        guard let spec = config["trustedRoots"] as? [String: Any] else {
            throw HarnessError("config.trustedRoots is missing")
        }
        let source = spec["source"] as? String
        if source == "builtin" {
            let name = spec["name"] as? String
            if name == "apple-jws-roots" { return appleJwsRoots() }
            if name == "apple-receipt-roots" { return appleReceiptRoots() }
            throw HarnessError("unknown builtin root set \"\(name ?? "nil")\"")
        }
        if source == "fixtures" {
            guard let ids = spec["fixtures"] as? [String] else {
                throw HarnessError("trustedRoots.fixtures is not a list of fixture ids")
            }
            return try ids.map { try bytes(of: $0) }
        }
        throw HarnessError("unknown trustedRoots source \"\(source ?? "nil")\"")
    }

    func jwsVerifier(_ config: [String: Any]) throws -> JwsVerifier {
        var environments = unmatchableEnvironments
        if let names = config["acceptedEnvironments"] as? [String] {
            environments = Set(try names.map { name in
                guard let environment = AppleEnvironment(rawValue: name) else {
                    throw HarnessError("unknown environment \"\(name)\"")
                }
                return environment
            })
        }
        let maxSignedAgeSeconds = (config["maxSignedAgeSeconds"] as? NSNumber)?.int64Value
        return try JwsVerifier(
            trustedRoots: try trustedRoots(config),
            bundleId: config["bundleId"] as? String ?? unmatchableBundleId,
            acceptedEnvironments: environments,
            appAppleId: (config["appAppleId"] as? NSNumber)?.int64Value,
            maxSignedAgeMillis: maxSignedAgeSeconds.map { $0 * 1000 })
    }

    /// Dispatches one case on its `operation`. Everything it returns is fed
    /// to ``normalize(_:)``; everything it throws is a verdict only when it
    /// is a ``VerificationError``.
    func invoke(operation: String, config: [String: Any], input: Data) async throws -> Any {
        switch operation {
        case "verifyTransaction":
            return try await jwsVerifier(config).verifyTransaction(try Self.text(input))
        case "verifyAppTransaction":
            return try await jwsVerifier(config).verifyAppTransaction(try Self.text(input))
        case "verifyRaw":
            return try await jwsVerifier(config).verifyRaw(try Self.text(input))
        case "verifyReceipt":
            guard let bundleId = config["bundleId"] as? String else {
                throw HarnessError("config.bundleId is missing")
            }
            let verifier = try ReceiptVerifier(trustedRoots: try trustedRoots(config),
                                               bundleId: bundleId)
            let guid = try (config["deviceGuidHex"] as? String).map(Self.hexBytes)
            return try await verifier.verify(receipt: input, deviceGuid: guid)
        case "verifyReceiptEndpoint":
            guard let environment = config["environment"] as? String,
                  environment == "Production" || environment == "Sandbox" else {
                throw HarnessError("config.environment must be Production or Sandbox")
            }
            let endpoint = try VerifyReceiptEndpoint(trustedRoots: try trustedRoots(config),
                                                     production: environment == "Production")
            return await endpoint.verifyReceipt(["receipt-data": input.base64EncodedString()])
        default:
            throw HarnessError("no adapter for operation \"\(operation)\"")
        }
    }

    private static func text(_ data: Data) throws -> String {
        guard let text = String(data: data, encoding: .utf8) else {
            throw HarnessError("input fixture is not valid UTF-8")
        }
        return text
    }

    private static func hexBytes(_ hex: String) throws -> Data {
        var bytes: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            guard let next = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex),
                  let byte = UInt8(hex[index..<next], radix: 16) else {
                throw HarnessError("\"\(hex)\" is not a hex byte string")
            }
            bytes.append(byte)
            index = next
        }
        return Data(bytes)
    }
}

// MARK: - result normalization

/// Renders a returned value into the language-neutral shape the field paths
/// are written against: dates as ISO-8601 UTC, binary as lowercase hex (also
/// under `<name>Hex`, the spelling cases.json uses for a byte field), a
/// struct's stored properties as an object keyed by property name, and a
/// dictionary's keys as strings. `NSNull` stands for "present but null"; the
/// field paths treat that and "absent" alike.
private func normalize(_ raw: Any) -> Any {
    guard let value = unwrapOptional(raw), !(value is NSNull) else { return NSNull() }
    if let date = value as? Date { return isoUTC(date) }
    if let data = value as? Data { return hexString(data) }
    if let string = value as? String { return string }
    if let list = value as? [Any] { return list.map(normalize) }
    if let object = value as? [String: Any] { return object.mapValues(normalize) }
    let mirror = Mirror(reflecting: value)
    guard let style = mirror.displayStyle else { return value }
    switch style {
    case .collection:
        return mirror.children.map { normalize($0.value) }
    case .dictionary:
        var object: [String: Any] = [:]
        for child in mirror.children {
            let pair = Mirror(reflecting: child.value).children.map { $0.value }
            guard pair.count == 2 else { continue }
            object[(pair[0] as? String) ?? "\(pair[0])"] = normalize(pair[1])
        }
        return object
    case .struct:
        // Every result this library returns is a struct, a collection, a
        // dictionary or a scalar, so classes deliberately fall through to the
        // scalar case below: NSNumber and NSString are classes, and reflecting
        // over them would turn a number into an empty object.
        var object: [String: Any] = [:]
        for child in mirror.children {
            guard let label = child.label else { continue }
            object[label] = normalize(child.value)
            if let unwrapped = unwrapOptional(child.value), unwrapped is Data {
                object[label + "Hex"] = object[label]
            }
        }
        return object
    default:
        return value
    }
}

/// `nil` for `Optional.none` at any depth, the payload otherwise.
private func unwrapOptional(_ value: Any) -> Any? {
    let mirror = Mirror(reflecting: value)
    guard mirror.displayStyle == .optional else { return value }
    guard let child = mirror.children.first else { return nil }
    return unwrapOptional(child.value)
}

/// ISO-8601 UTC, dropping milliseconds when they are zero.
private func isoUTC(_ date: Date) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.timeZone = TimeZone(identifier: "UTC")
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let text = formatter.string(from: date)
    return text.hasSuffix(".000Z")
        ? String(text.dropLast(5)) + "Z" : text
}

private func hexString(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

// MARK: - field paths

/// A path step is either a name (`bundleId`, `length`) or a bracket
/// (`[9999]`, `[0]`, `[productId=com.example.app.vip]`). Bracket contents may
/// hold dots, so the split cannot be a plain `split(separator: ".")`.
private enum PathStep {
    case name(String)
    case bracket(String)
}

private func pathSteps(_ path: String) throws -> [PathStep] {
    var steps: [PathStep] = []
    var name = ""
    var index = path.startIndex
    while index < path.endIndex {
        switch path[index] {
        case ".":
            if !name.isEmpty { steps.append(.name(name)); name = "" }
            index = path.index(after: index)
        case "[":
            if !name.isEmpty { steps.append(.name(name)); name = "" }
            guard let close = path[index...].firstIndex(of: "]") else {
                throw HarnessError("unparseable field path \"\(path)\"")
            }
            steps.append(.bracket(String(path[path.index(after: index)..<close])))
            index = path.index(after: close)
        default:
            name.append(path[index])
            index = path.index(after: index)
        }
    }
    if !name.isEmpty { steps.append(.name(name)) }
    guard !steps.isEmpty else { throw HarnessError("unparseable field path \"\(path)\"") }
    return steps
}

/// `nil` means "no such field"; `NSNull` means "present and null".
private func resolve(_ root: Any, _ path: String) throws -> Any? {
    var current: Any? = root
    for step in try pathSteps(path) {
        guard let value = current, !(value is NSNull) else { return nil }
        switch step {
        case .name(let name):
            if name == "length", let list = value as? [Any] {
                current = list.count
            } else if let object = value as? [String: Any] {
                current = object[name]
            } else {
                return nil
            }
        case .bracket(let bracket):
            if let separator = bracket.firstIndex(of: "="), separator != bracket.startIndex {
                let key = String(bracket[bracket.startIndex..<separator])
                let wanted = String(bracket[bracket.index(after: separator)...])
                guard let list = value as? [Any] else {
                    throw HarnessError("\(path): [\(bracket)] does not select from a list")
                }
                let matches = list.compactMap { $0 as? [String: Any] }
                    .filter { ($0[key] as? String) == wanted }
                guard matches.count == 1 else {
                    throw HarnessError("\(path): [\(bracket)] must select exactly one element, "
                        + "selected \(matches.count)")
                }
                current = matches[0]
            } else if let list = value as? [Any] {
                guard let index = Int(bracket), index >= 0, index < list.count else { return nil }
                current = list[index]
            } else if let object = value as? [String: Any] {
                current = object[bracket]
            } else {
                return nil
            }
        }
    }
    return current
}

/// Subset semantics: a pinned field must match, everything else the call
/// returned is ignored. `null` in the vectors means "absent or unset".
private func matches(_ actual: Any?, _ expected: Any) -> Bool {
    if expected is NSNull {
        guard let actual else { return true }
        return actual is NSNull
    }
    guard let actual, !(actual is NSNull) else { return false }
    if let text = expected as? String { return (actual as? String) == text }
    if let want = numericValue(expected), let got = numericValue(actual) { return want == got }
    return false
}

private func numericValue(_ value: Any) -> Double? {
    switch value {
    case let number as NSNumber: return number.doubleValue
    case let number as Int: return Double(number)
    case let number as Int64: return Double(number)
    case let number as Double: return number
    default: return nil
    }
}

private func describe(_ value: Any?) -> String {
    guard let value, !(value is NSNull) else { return "null" }
    if let text = value as? String { return "\"\(text)\"" }
    return "\(value)"
}

// MARK: - the cases

/// One test method per `operation`, each running every case in
/// fixtures/cases.json that carries it.
///
/// XCTest cannot register a test method per case at runtime on both platforms
/// this package builds for — `XCTestCase(name:testClosure:)` exists only in
/// swift-corelibs-xctest and `XCTContext.runActivity` only on Darwin — so the
/// grouping is the coarsest thing the adapter is allowed to know about a
/// case: its operation. Every assertion message names the case id, and
/// `continueAfterFailure` stays on, so one failing case neither hides the
/// rest of its group nor reports under another case's name.
final class ConformanceCasesTests: XCTestCase {
    /// The operations the methods below cover, one method each.
    static let coveredOperations: Set<String> = [
        "verifyTransaction", "verifyAppTransaction", "verifyRaw",
        "verifyReceipt", "verifyReceiptEndpoint",
    ]

    override func setUp() {
        super.setUp()
        continueAfterFailure = true
    }

    func testVerifyTransactionCases() async { await run(operation: "verifyTransaction") }

    func testVerifyAppTransactionCases() async { await run(operation: "verifyAppTransaction") }

    func testVerifyRawCases() async { await run(operation: "verifyRaw") }

    func testVerifyReceiptCases() async { await run(operation: "verifyReceipt") }

    func testVerifyReceiptEndpointCases() async { await run(operation: "verifyReceiptEndpoint") }

    /// Prints the cases this implementation cannot run and why, and pins that
    /// every operation in the file is claimed by a method above — a new
    /// operation must not slip in unrun.
    func testReportsItsCoverageAndTheCasesItCannotRun() throws {
        let vectors = try Vectors()
        XCTAssertEqual(Set(vectors.cases.compactMap { $0["operation"] as? String }),
                       Self.coveredOperations,
                       "cases.json carries an operation no test method runs")
        let skipped = vectors.cases.filter { $0["clock"] != nil }
            .compactMap { $0["id"] as? String }
        for id in skipped {
            print("conformance SKIP \(id): \(noClockSeam)")
        }
        print("conformance: \(vectors.cases.count) cases, \(skipped.count) skipped for lack of "
            + "a clock seam \(skipped)")
    }

    private func run(operation: String) async {
        let vectors: Vectors
        do {
            vectors = try Vectors()
        } catch {
            XCTFail("harness error: \(error)")
            return
        }
        let selected = vectors.cases.filter { ($0["operation"] as? String) == operation }
        XCTAssertFalse(selected.isEmpty, "cases.json carries no \(operation) case")
        for kase in selected {
            await run(kase, from: vectors)
        }
    }

    private func run(_ kase: [String: Any], from vectors: Vectors) async {
        let id = kase["id"] as? String ?? "<case without an id>"
        guard let operation = kase["operation"] as? String,
              let config = kase["config"] as? [String: Any],
              let fixture = (kase["input"] as? [String: Any])?["fixture"] as? String,
              let expected = kase["expected"] as? [String: Any],
              let status = expected["status"] as? String else {
            XCTFail("harness error: \(id): the case is missing a required member")
            return
        }
        if kase["clock"] != nil {
            print("conformance SKIP \(id): \(noClockSeam)")
            return
        }
        let result: Any
        do {
            result = try await vectors.invoke(operation: operation, config: config,
                                              input: try vectors.bytes(of: fixture))
        } catch let error as VerificationError {
            guard status == "error" else {
                XCTFail("\(id): expected success but threw \(error.reason.rawValue)")
                return
            }
            XCTAssertEqual(error.reason.rawValue, expected["reason"] as? String ?? "<no reason>",
                           "\(id): reason")
            return
        } catch {
            // Only a VerificationError carries a canonical Reason. Anything
            // else is a defect in the library or in this harness, and must
            // never be read as one of the expected reasons.
            XCTFail("harness error: \(id): \(operation) threw \(type(of: error)) (\(error)), "
                + "which is not a VerificationError")
            return
        }
        guard status == "ok" else {
            XCTFail("\(id): expected \(expected["reason"] as? String ?? "an error") "
                + "but the call returned a value")
            return
        }
        guard let fields = expected["fields"] as? [String: Any] else {
            XCTFail("harness error: \(id): expected.fields is missing")
            return
        }
        let actual = normalize(result)
        for path in fields.keys.sorted() {
            guard let want = fields[path] else { continue }
            do {
                let got = try resolve(actual, path)
                XCTAssertTrue(matches(got, want),
                              "\(id): \(path): expected \(describe(want)), got \(describe(got))")
            } catch {
                XCTFail("harness error: \(id): \(error)")
            }
        }
    }
}
