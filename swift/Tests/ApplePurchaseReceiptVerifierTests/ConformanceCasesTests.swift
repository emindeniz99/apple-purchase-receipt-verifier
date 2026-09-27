import Crypto
import Foundation
import XCTest
@testable import ApplePurchaseReceiptVerifier

// Runs fixtures/cases.json — the normative cross-language conformance
// vectors for the 0.7 API — against this implementation. The adapter below
// knows nothing about any individual case: it loads the file, resolves
// fixture ids to bytes, builds a Verifier from the generic config, dispatches
// on "operation", and evaluates "expected" against the result. A vector that
// disagrees with the library is a bug report against one of the two; it is
// never something to special-case here.

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

// MARK: - the vector file

/// Just enough of cases.json for `JSONDecoder` to read every
/// `decodeBase64` case's texts.
private struct TextsFile: Decodable {
    struct Case: Decodable {
        struct Input: Decodable { let texts: [String]? }
        let id: String
        let input: Input?
    }
    let cases: [Case]
}

private struct Vectors {
    let fixtures: [String: [String: Any]]
    let cases: [[String: Any]]
    /// decodeBase64 texts by case id, read with `JSONDecoder` rather than
    /// `JSONSerialization`: on both Darwin and Linux, `JSONSerialization`
    /// builds its strings through the platform's own bridging and drops a
    /// leading U+FEFF, so a text that starts with a byte-order mark would
    /// reach this harness without it and the group would test a different
    /// spelling than the file states (see `base64/reject-non-ascii`, whose
    /// third text IS a bare BOM followed by valid base64 — the case only
    /// makes sense if that BOM survives the read).
    let base64Texts: [String: [String]]

    init() throws {
        let data = try Data(contentsOf: fixturesDirectory.appendingPathComponent("cases.json"))
        guard let file = try JSONSerialization.jsonObject(with: data) as? [String: Any],
            let fixtures = file["fixtures"] as? [String: [String: Any]],
            let cases = file["cases"] as? [[String: Any]]
        else { throw HarnessError("fixtures/cases.json is not the expected JSON object") }
        self.fixtures = fixtures
        self.cases = cases
        let exact = try JSONDecoder().decode(TextsFile.self, from: data)
        var texts: [String: [String]] = [:]
        for kase in exact.cases {
            if let caseTexts = kase.input?.texts { texts[kase.id] = caseTexts }
        }
        self.base64Texts = texts
    }

    /// Decodes a registered fixture to its logical bytes (fixture.codec) and
    /// checks them against the digest the file records — the anti-drift
    /// guarantee that every fixture this adapter loads is hashed here, a
    /// mismatch being a harness failure, never a verdict about a payload.
    func bytes(of id: String) throws -> [UInt8] {
        let decoded = try decode(id)
        guard let expected = fixtures[id]?["contentSha256"] as? String else {
            throw HarnessError("fixture \"\(id)\" registers no contentSha256")
        }
        let actual = Data(SHA256.hash(data: decoded)).map { String(format: "%02x", $0) }.joined()
        guard actual == expected.lowercased() else {
            throw HarnessError(
                "fixture \"\(id)\" has content sha256 \(actual), but cases.json records \(expected)")
        }
        return decoded
    }

    func codec(of id: String) throws -> String {
        guard let codec = fixtures[id]?["codec"] as? String else {
            throw HarnessError("cases.json registers no fixture \"\(id)\"")
        }
        return codec
    }

    private func decode(_ id: String) throws -> [UInt8] {
        guard let entry = fixtures[id], let path = entry["path"] as? String,
            let codec = entry["codec"] as? String
        else { throw HarnessError("cases.json registers no fixture \"\(id)\"") }
        let raw = try Data(contentsOf: fixturesDirectory.appendingPathComponent(path))
        switch codec {
        case "raw":
            return [UInt8](raw)
        case "base64":
            guard let text = String(data: raw, encoding: .utf8),
                let decoded = Data(base64Encoded: text, options: [.ignoreUnknownCharacters])
            else { throw HarnessError("fixture \"\(id)\" is not decodable base64") }
            return [UInt8](decoded)
        case "utf8":
            guard let text = String(data: raw, encoding: .utf8) else {
                throw HarnessError("fixture \"\(id)\" is not valid UTF-8")
            }
            return [UInt8](text.trimmingCharacters(in: .whitespacesAndNewlines).utf8)
        case "text":
            return [UInt8](raw)
        default:
            throw HarnessError("unknown fixture codec \"\(codec)\"")
        }
    }

    /// The string a client sends for `verifyReceipt`/`receipt-data`: a
    /// `text` fixture's bytes are already that string, verbatim; a `raw` or
    /// `base64` fixture holds DER, re-encoded here as canonical standard
    /// base64; a `utf8` fixture (should one register as a receipt input)
    /// already decodes to string bytes, same as `text`.
    func receiptBase64String(fixture id: String) throws -> String {
        let logical = try bytes(of: id)
        let codec = try codec(of: id)
        if codec == "raw" || codec == "base64" {
            return standardBase64Encode(logical)
        }
        return String(decoding: logical, as: UTF8.self)
    }

    /// The string handed to `verifySignedData`: the fixture's logical bytes
    /// as a string, whatever the codec.
    func textString(fixture id: String) throws -> String {
        String(decoding: try bytes(of: id), as: UTF8.self)
    }

    func trustedRootsDER(_ config: [String: Any]) throws -> [[UInt8]]? {
        guard let spec = config["trustedRoots"] as? [String: Any], let source = spec["source"] as? String
        else { throw HarnessError("config.trustedRoots is missing") }
        if source == "defaults" { return nil }
        if source == "fixtures" {
            guard let ids = spec["fixtures"] as? [String] else {
                throw HarnessError("trustedRoots.fixtures is not a list of fixture ids")
            }
            return try ids.map { try bytes(of: $0) }
        }
        throw HarnessError("unknown trustedRoots source \"\(source)\"")
    }

    func config(_ config: [String: Any], clockMillis: Int64?) throws -> Config {
        let roots = try trustedRootsDER(config)
        if roots == nil, clockMillis == nil { return Config.defaults() }
        var builder = Config.builder()
        if let roots { builder = try builder.roots(roots) }
        if let clockMillis { builder = builder.clock { clockMillis } }
        return try builder.build()
    }
}

/// A case's optional `clock.now`, parsed to epoch milliseconds.
private func clockMillis(_ kase: [String: Any]) throws -> Int64? {
    guard let clock = kase["clock"] as? [String: Any] else { return nil }
    guard let text = clock["now"] as? String else { throw HarnessError("case clock has no \"now\"") }
    guard let millis = parseReceiptDate(text) else {
        throw HarnessError("clock.now \"\(text)\" is not an ISO-8601 instant this harness can parse")
    }
    return millis
}

// MARK: - JSON pointers (RFC 6901 + the `[key=value]` extension)

private func unescapeToken(_ token: Substring) -> String {
    String(token).replacingOccurrences(of: "~1", with: "/").replacingOccurrences(of: "~0", with: "~")
}

private func bracketSelector(_ token: String) -> (key: String, value: String)? {
    guard token.hasPrefix("["), token.hasSuffix("]"), token.count >= 2 else { return nil }
    let inner = token.dropFirst().dropLast()
    guard let eq = inner.firstIndex(of: "=") else { return nil }
    return (String(inner[..<eq]), String(inner[inner.index(after: eq)...]))
}

/// `nil` means "no such value"; `NSNull` means "present and JSON null".
private func resolvePointer(_ root: Any, _ pointer: String) throws -> Any? {
    guard pointer.hasPrefix("/") else { throw HarnessError("pointer \"\(pointer)\" must start with '/'") }
    var current: Any? = root
    for rawToken in pointer.dropFirst().split(separator: "/", omittingEmptySubsequences: false) {
        guard let value = current, !(value is NSNull) else { return nil }
        let token = unescapeToken(rawToken)
        if let selector = bracketSelector(token) {
            guard let array = value as? [Any] else {
                throw HarnessError("\(pointer): \(token) does not select from an array")
            }
            let matches = array.filter { ($0 as? [String: Any])?[selector.key] as? String == selector.value }
            guard matches.count == 1 else {
                throw HarnessError("\(pointer): \(token) must select exactly one element, selected \(matches.count)")
            }
            current = matches[0]
        } else if let array = value as? [Any] {
            guard let index = Int(token), index >= 0, index < array.count else { return nil }
            current = array[index]
        } else if let object = value as? [String: Any] {
            current = object[token]
        } else {
            return nil
        }
    }
    return current
}

private func lengthAt(_ root: Any, _ pointer: String) throws -> Int? {
    guard let value = try resolvePointer(root, pointer) else { return nil }
    guard let array = value as? [Any] else { throw HarnessError("\(pointer) is not an array") }
    return array.count
}

/// Subset semantics: a pinned field must match, everything else the call
/// returned is ignored. `null` in the vectors means "absent or unset".
///
/// The `Bool` check runs before the `NSNumber` one, so a boolean is never
/// accepted as a match for a number and vice versa — on Linux,
/// `JSONSerialization` (swift-corelibs-foundation) hands `true`/`false`
/// back as a genuine Swift `Bool`, not a boolean-flavoured `NSNumber` as
/// Darwin's `CFBoolean` bridging would, so a plain `as? Bool` cast already
/// tells the two apart without reaching for `CFGetTypeID`, which is not
/// available outside an explicit `CoreFoundation` import. Integers compare
/// by their exact digits (`download_id` can exceed 2^53, where `Double`
/// starts rounding); anything else compares as a `Double`.
private func fieldMatches(_ actual: Any?, _ expected: Any) -> Bool {
    if expected is NSNull { return actual == nil || actual is NSNull }
    guard let actual, !(actual is NSNull) else { return false }
    if let text = expected as? String { return (actual as? String) == text }
    if let flag = expected as? Bool { return (actual as? Bool) == flag }
    guard let expectedNumber = expected as? NSNumber, let actualNumber = actual as? NSNumber,
        !(actual is Bool)
    else { return false }
    if let want = int64IfExact(expectedNumber), let got = int64IfExact(actualNumber) { return want == got }
    return expectedNumber.doubleValue == actualNumber.doubleValue
}

/// Deep equality over parsed JSON: objects by key in any order, arrays
/// element by element, scalars as ``fieldMatches`` compares them (a boolean
/// never equals a number, integers by their exact digits).
func sameJsonValue(_ actual: Any, _ expected: Any) -> Bool {
    if let want = expected as? [String: Any] {
        guard let got = actual as? [String: Any], got.count == want.count else { return false }
        return want.allSatisfy { key, value in got[key].map { sameJsonValue($0, value) } ?? false }
    }
    if let want = expected as? [Any] {
        guard let got = actual as? [Any], got.count == want.count else { return false }
        return zip(got, want).allSatisfy { sameJsonValue($0, $1) }
    }
    if expected is NSNull { return actual is NSNull }
    return fieldMatches(actual, expected)
}

private func int64IfExact(_ number: NSNumber) -> Int64? {
    switch String(cString: number.objCType) {
    case "q", "l", "i", "s": return number.int64Value
    default: return nil
    }
}

private func describeExpected(_ value: Any?) -> String {
    guard let value, !(value is NSNull) else { return "null" }
    if let text = value as? String { return "\"\(text)\"" }
    return "\(value)"
}

// MARK: - measuring maxMillis

/// Runs `body` once (warm-up, discarded) then measures a second run; fails
/// when the second run exceeds `limitMillis`.
private func withinBudget(_ limitMillis: Int, _ id: String, _ body: () -> Void) {
    body()
    let start = Date()
    body()
    let elapsedMillis = Date().timeIntervalSince(start) * 1000
    XCTAssertLessThanOrEqual(
        elapsedMillis, Double(limitMillis), "\(id): took \(elapsedMillis) ms, budget \(limitMillis) ms")
}

// MARK: - the cases

final class ConformanceCasesTests: XCTestCase {
    static let coveredOperations: Set<String> = [
        "verifyReceipt", "verifySignedData", "verifyReceiptEndpoint", "decodeBase64",
    ]

    override func setUp() {
        super.setUp()
        continueAfterFailure = true
    }

    func testVerifyReceiptCases() throws { try run(operation: "verifyReceipt") }
    func testVerifySignedDataCases() throws { try run(operation: "verifySignedData") }
    func testVerifyReceiptEndpointCases() throws { try run(operation: "verifyReceiptEndpoint") }
    func testDecodeBase64Cases() throws { try run(operation: "decodeBase64") }

    /// Pins that every operation in the file is claimed by a method above,
    /// so a new operation cannot slip in unrun.
    func testReportsItsCoverage() throws {
        let vectors = try Vectors()
        XCTAssertEqual(
            Set(vectors.cases.compactMap { $0["operation"] as? String }), Self.coveredOperations,
            "cases.json carries an operation no test method runs")
        print("conformance: \(vectors.cases.count) cases, \(vectors.fixtures.count) fixtures")
    }

    func testEveryRegisteredFixtureMatchesItsRecordedDigest() throws {
        let vectors = try Vectors()
        XCTAssertFalse(vectors.fixtures.isEmpty, "cases.json registers no fixtures")
        for id in vectors.fixtures.keys.sorted() {
            XCTAssertNoThrow(try vectors.bytes(of: id), "fixture \(id)")
        }
    }

    private func run(operation: String) throws {
        let vectors = try Vectors()
        let selected = vectors.cases.filter { ($0["operation"] as? String) == operation }
        XCTAssertFalse(selected.isEmpty, "cases.json carries no \(operation) case")
        var ran = Set<String>()
        for kase in selected {
            let id = kase["id"] as? String ?? "<case without an id>"
            ran.insert(id)
            do {
                try runOne(kase, id: id, operation: operation, vectors: vectors)
            } catch {
                XCTFail("harness error: \(id): \(error)")
            }
        }
        let missing = selected.compactMap { $0["id"] as? String }.filter { !ran.contains($0) }
        XCTAssertTrue(missing.isEmpty, "\(missing.count) \(operation) cases did not run: \(missing.joined(separator: ", "))")
    }

    private func runOne(_ kase: [String: Any], id: String, operation: String, vectors: Vectors) throws {
        if operation == "decodeBase64" {
            try runDecodeBase64(kase, id: id, texts: vectors.base64Texts[id])
            return
        }
        guard let config = kase["config"] as? [String: Any], let input = kase["input"] as? [String: Any],
            let expected = kase["expected"] as? [String: Any]
        else { throw HarnessError("\(id): the case is missing a required member") }
        let clock = try clockMillis(kase)
        let maxMillis = kase["maxMillis"] as? Int

        if operation == "verifyReceiptEndpoint" {
            guard let environmentName = config["environment"] as? String else {
                throw HarnessError("\(id): config.environment is missing")
            }
            let environment: Environment
            switch environmentName {
            case "PRODUCTION": environment = .production
            case "SANDBOX": environment = .sandbox
            default: throw HarnessError("\(id): config.environment must be PRODUCTION or SANDBOX")
            }
            let verifierConfig = try vectors.config(config, clockMillis: clock)
            let verifier = Verifier(config: verifierConfig)
            let requestJSON = try endpointRequestJSON(input, vectors: vectors)
            var response = ""
            let call = { response = verifier.verifyReceiptEndpoint(environment: environment, requestJson: requestJSON) }
            if let maxMillis { withinBudget(maxMillis, id, call) } else { call() }
            try assertEndpoint(response, expected: expected, id: id)
            return
        }

        let verifierConfig = try vectors.config(config, clockMillis: clock)
        let verifier = Verifier(config: verifierConfig)

        if operation == "verifyReceipt" {
            guard let fixtureId = input["fixture"] as? String else {
                throw HarnessError("\(id): input carries no fixture")
            }
            let base64 = try vectors.receiptBase64String(fixture: fixtureId)
            var result: VerificationResult<ReceiptPayload>!
            let call = { result = verifier.verifyReceipt(base64: base64) }
            if let maxMillis { withinBudget(maxMillis, id, call) } else { call() }
            try assertReceiptResult(result, expected: expected, id: id)
            return
        }

        if operation == "verifySignedData" {
            guard let fixtureId = input["fixture"] as? String else {
                throw HarnessError("\(id): input carries no fixture")
            }
            let jws = try vectors.textString(fixture: fixtureId)
            var result: VerificationResult<JsonPayload>!
            let call = { result = verifier.verifySignedData(jws: jws) }
            if let maxMillis { withinBudget(maxMillis, id, call) } else { call() }
            try assertSignedDataResult(result, expected: expected, id: id)
            return
        }

        throw HarnessError("\(id): no adapter for operation \"\(operation)\"")
    }

    private func endpointRequestJSON(_ input: [String: Any], vectors: Vectors) throws -> String {
        if let bodyId = input["requestBody"] as? String {
            return try vectors.textString(fixture: bodyId)
        }
        guard let fixtureId = input["fixture"] as? String else {
            throw HarnessError("input carries neither fixture nor requestBody")
        }
        let string = try vectors.receiptBase64String(fixture: fixtureId)
        return jsonText(["receipt-data": string])
    }

    // MARK: assertions

    private func assertReceiptResult(_ result: VerificationResult<ReceiptPayload>, expected: [String: Any], id: String) throws {
        if let allowed = expected["oneOf"] as? [String] {
            let outcome = result.failure?.reason.rawValue ?? "ok"
            XCTAssertTrue(allowed.contains(outcome), "\(id): answered \(outcome), want one of \(allowed)")
            return
        }
        guard let status = expected["status"] as? String else { throw HarnessError("\(id): expected.status missing") }
        if status == "ok" {
            guard let payload = result.payload else {
                XCTFail("\(id): expected ok but got \(result.failure.map { String(describing: $0.reason) } ?? "no result")")
                return
            }
            let json = payload.toJson()
            guard let parsed = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any] else {
                XCTFail("\(id): toJson() did not produce a JSON object")
                return
            }
            // Same value, not same bytes: whitespace, key order and escaping
            // are free (docs/design/0.7-api.md "Our JSON").
            if let wantJson = expected["toJson"] as? String {
                let want = try JSONSerialization.jsonObject(with: Data(wantJson.utf8))
                XCTAssertTrue(sameJsonValue(parsed, want), "\(id): toJson value\n  want: \(wantJson)\n  got:  \(json)")
            }
            try assertFieldsAndLengths(parsed, expected: expected, id: id)
        } else if status == "error" {
            try assertError(result.failure, expected: expected, id: id)
        } else {
            XCTFail("\(id): unrecognised expected shape")
        }
    }

    private func assertSignedDataResult(_ result: VerificationResult<JsonPayload>, expected: [String: Any], id: String) throws {
        if let allowed = expected["oneOf"] as? [String] {
            let outcome = result.failure?.reason.rawValue ?? "ok"
            XCTAssertTrue(allowed.contains(outcome), "\(id): answered \(outcome), want one of \(allowed)")
            return
        }
        guard let status = expected["status"] as? String else { throw HarnessError("\(id): expected.status missing") }
        if status == "ok" {
            guard let payload = result.payload else {
                XCTFail("\(id): expected ok but got \(result.failure.map { String(describing: $0.reason) } ?? "no result")")
                return
            }
            guard let parsed = try JSONSerialization.jsonObject(with: Data(payload.json.utf8)) as? [String: Any] else {
                XCTFail("\(id): json() did not produce a JSON object")
                return
            }
            try assertFieldsAndLengths(parsed, expected: expected, id: id)
        } else if status == "error" {
            try assertError(result.failure, expected: expected, id: id)
        } else {
            XCTFail("\(id): unrecognised expected shape")
        }
    }

    private func assertEndpoint(_ response: String, expected: [String: Any], id: String) throws {
        guard let parsed = try JSONSerialization.jsonObject(with: Data(response.utf8)) as? [String: Any] else {
            XCTFail("\(id): endpoint response is not a JSON object: \(response)")
            return
        }
        try assertFieldsAndLengths(parsed, expected: expected, id: id)
    }

    private func assertFieldsAndLengths(_ parsed: [String: Any], expected: [String: Any], id: String) throws {
        if let fields = expected["fields"] as? [String: Any] {
            for pointer in fields.keys.sorted() {
                guard let want = fields[pointer] else { continue }
                let got = try resolvePointer(parsed, pointer)
                XCTAssertTrue(
                    fieldMatches(got, want), "\(id): \(pointer): expected \(describeExpected(want)), got \(describeExpected(got))")
            }
        }
        if let lengths = expected["lengths"] as? [String: Any] {
            for pointer in lengths.keys.sorted() {
                guard let want = (lengths[pointer] as? NSNumber)?.intValue else { continue }
                let got = try lengthAt(parsed, pointer)
                XCTAssertEqual(got, want, "\(id): \(pointer) length")
            }
        }
    }

    private func assertError(_ failure: Failure?, expected: [String: Any], id: String) throws {
        guard let failure else {
            XCTFail("\(id): expected an error but the call verified")
            return
        }
        let wantReason = expected["reason"] as? String ?? "<no reason>"
        XCTAssertEqual(failure.reason.rawValue, wantReason, "\(id): reason")
        if let mustNotContain = expected["messageMustNotContain"] as? [Int] {
            let scalars = Set(failure.message.unicodeScalars.map { $0.value })
            for codepoint in mustNotContain {
                XCTAssertFalse(
                    scalars.contains(UInt32(codepoint)), "\(id): message contains forbidden code point U+\(String(codepoint, radix: 16))")
            }
        }
    }

    // MARK: decodeBase64

    private func runDecodeBase64(_ kase: [String: Any], id: String, texts: [String]?) throws {
        guard let decoders = kase["decoders"] as? [String], !decoders.isEmpty, let texts, !texts.isEmpty,
            let expected = kase["expected"] as? [String: Any], let status = expected["status"] as? String
        else { throw HarnessError("\(id): a decodeBase64 case needs decoders, input.texts and expected.status") }
        let ok = status == "ok"
        let wantHex = ok ? (expected["bytesHex"] as? String ?? "") : ""
        for decoder in decoders {
            for (index, text) in texts.enumerated() {
                let at = "\(id): \(decoder) texts[\(index)] \(text.debugDescription)"
                let decoded: [UInt8]?
                switch decoder {
                case "receipt-data", "x5c":
                    decoded = decodeReceiptBase64(text)
                default:
                    throw HarnessError("\(id): no decoder \"\(decoder)\"")
                }
                switch (decoded, ok) {
                case (let bytes?, true):
                    XCTAssertEqual(bytes.map { String(format: "%02x", $0) }.joined(), wantHex, at)
                case (nil, false):
                    break
                case (let bytes?, false):
                    XCTFail("\(at) was accepted (decoded to \(bytes.map { String(format: "%02x", $0) }.joined()))")
                case (nil, true):
                    XCTFail("\(at) was refused, want \(wantHex)")
                }
            }
        }
    }
}
