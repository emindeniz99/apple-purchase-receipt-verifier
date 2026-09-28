import Foundation

/// Parses JSON text into the Foundation shapes the conformance harness
/// compares (`[String: Any]`, `[Any]`, `String`, `Bool`, `NSNumber`,
/// `NSNull`), keeping the LAST member when an object names a key twice.
///
/// `JSONSerialization` cannot be used for text the library hands back "as
/// signed": its duplicate-key policy is the platform's, not ours.
/// swift-corelibs-foundation (Linux) keeps the last member, Darwin
/// Foundation keeps the first, so a payload stating `signedDate` twice read
/// back a different field on each platform although the library's verdict
/// was the same. The design (docs/design/0.7-api.md) says the last member
/// wins, as it does in the library's own reader.
///
/// Integers that fit `Int64` become `NSNumber(value: Int64)`, so the
/// harness compares them by exact digits; any other number is a `Double`.
func parseJsonLastWins(_ text: String) throws -> Any {
    var reader = LastWinsJsonReader(bytes: Array(text.utf8))
    reader.skipWhitespace()
    let value = try reader.value()
    reader.skipWhitespace()
    guard reader.at == reader.bytes.count else { throw LastWinsJsonError("trailing content") }
    return value
}

struct LastWinsJsonError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

private struct LastWinsJsonReader {
    let bytes: [UInt8]
    var at = 0

    init(bytes: [UInt8]) { self.bytes = bytes }

    mutating func skipWhitespace() {
        while at < bytes.count, [0x20, 0x09, 0x0A, 0x0D].contains(bytes[at]) { at += 1 }
    }

    mutating func next() throws -> UInt8 {
        guard at < bytes.count else { throw LastWinsJsonError("unexpected end of input") }
        defer { at += 1 }
        return bytes[at]
    }

    mutating func value() throws -> Any {
        guard at < bytes.count else { throw LastWinsJsonError("unexpected end of input") }
        switch bytes[at] {
        case 0x7B: return try object()
        case 0x5B: return try array()
        case 0x22: return try string()
        case 0x74: return try literal("true", true)
        case 0x66: return try literal("false", false)
        case 0x6E: return try literal("null", NSNull())
        default: return try number()
        }
    }

    mutating func object() throws -> [String: Any] {
        at += 1  // '{'
        var members: [String: Any] = [:]
        skipWhitespace()
        if at < bytes.count, bytes[at] == 0x7D {
            at += 1
            return members
        }
        while true {
            skipWhitespace()
            let name = try string()
            skipWhitespace()
            guard try next() == 0x3A else { throw LastWinsJsonError("expected ':'") }
            skipWhitespace()
            members[name] = try value()  // a later duplicate overwrites: last wins
            skipWhitespace()
            switch try next() {
            case 0x2C: continue
            case 0x7D: return members
            default: throw LastWinsJsonError("expected ',' or '}'")
            }
        }
    }

    mutating func array() throws -> [Any] {
        at += 1  // '['
        var elements: [Any] = []
        skipWhitespace()
        if at < bytes.count, bytes[at] == 0x5D {
            at += 1
            return elements
        }
        while true {
            skipWhitespace()
            elements.append(try value())
            skipWhitespace()
            switch try next() {
            case 0x2C: continue
            case 0x5D: return elements
            default: throw LastWinsJsonError("expected ',' or ']'")
            }
        }
    }

    mutating func literal(_ word: String, _ result: Any) throws -> Any {
        for byte in word.utf8 where try next() != byte { throw LastWinsJsonError("bad literal") }
        return result
    }

    mutating func number() throws -> NSNumber {
        let start = at
        while at < bytes.count, "+-0123456789.eE".utf8.contains(bytes[at]) { at += 1 }
        let text = String(decoding: bytes[start..<at], as: UTF8.self)
        if let integer = Int64(text) { return NSNumber(value: integer) }
        guard !text.isEmpty, let double = Double(text) else { throw LastWinsJsonError("bad number \(text)") }
        return NSNumber(value: double)
    }

    mutating func string() throws -> String {
        guard try next() == 0x22 else { throw LastWinsJsonError("expected '\"'") }
        var out: [UInt8] = []
        while true {
            let byte = try next()
            switch byte {
            case 0x22: return String(decoding: out, as: UTF8.self)
            case 0x5C: try escape(into: &out)
            default: out.append(byte)
            }
        }
    }

    mutating func escape(into out: inout [UInt8]) throws {
        let simple: [UInt8: UInt8] = [
            0x22: 0x22, 0x5C: 0x5C, 0x2F: 0x2F, 0x62: 0x08, 0x66: 0x0C, 0x6E: 0x0A, 0x72: 0x0D, 0x74: 0x09,
        ]
        let byte = try next()
        if let replacement = simple[byte] {
            out.append(replacement)
            return
        }
        guard byte == 0x75 else { throw LastWinsJsonError("bad escape") }
        var scalar = try hex4()
        if (0xD800...0xDBFF).contains(scalar), try next() == 0x5C, try next() == 0x75 {
            let low = try hex4()
            guard (0xDC00...0xDFFF).contains(low) else { throw LastWinsJsonError("bad surrogate pair") }
            scalar = 0x10000 + ((scalar - 0xD800) << 10) + (low - 0xDC00)
        }
        guard let unicode = Unicode.Scalar(scalar) else { throw LastWinsJsonError("lone surrogate") }
        out.append(contentsOf: Array(String(Character(unicode)).utf8))
    }

    mutating func hex4() throws -> UInt32 {
        var result: UInt32 = 0
        for _ in 0..<4 {
            guard let digit = UInt32(String(UnicodeScalar(try next())), radix: 16) else {
                throw LastWinsJsonError("bad \\u escape")
            }
            result = result << 4 | digit
        }
        return result
    }
}
