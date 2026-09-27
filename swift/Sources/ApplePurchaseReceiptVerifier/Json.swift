/// The JSON reader for the three documents this library parses: a JWS
/// header, a JWS payload and the endpoint's request body.
///
/// None of them is behind a signature when it is read, so the reader is
/// bounded (``maxJsonNestingDepth``, ``maxJsonNumberLength``,
/// ``maxJsonNameLength``) and allocates only what it keeps. It reads the
/// first value, which must be an object. ``wholeObjectMembers(_:)`` then
/// allows only whitespace after it, the rule for a JWS header and payload;
/// ``topLevelMembers(_:)`` stops at the object's closing brace and does not
/// read the rest, the endpoint's rule for a request body, as Apple's endpoint
/// does not read it either. The grammar is strict RFC 8259 inside the
/// object: no comments, no trailing commas, no leading zeros or `+`, no
/// `NaN`, no unescaped control characters, and only the escapes RFC 8259
/// defines.
///
/// Only the top-level members are handed back; nested values are validated
/// and skipped.

/// How deep a document may nest: arrays and objects open at once, the
/// outermost one included.
let maxJsonNestingDepth = 64

/// The longest number, in characters.
let maxJsonNumberLength = 1000

/// The longest member name, in UTF-16 units.
let maxJsonNameLength = 50_000

struct JsonError: Error, Sendable {
    let detail: String
    init(_ detail: String) { self.detail = detail }
}

/// A top-level member's value, reduced to what the callers read.
enum JsonValue: Equatable {
    /// A string, unescaped. A lone surrogate escape becomes U+FFFD.
    case string(String)
    /// A number, as written, and whether it has no fraction or exponent.
    case number(text: String, integer: Bool)
    /// An array whose elements are all strings.
    case strings([String])
    /// Anything else: an object, a mixed array, `true`, `false`, `null`.
    case other
}

/// The top-level members of the object `text` starts with, in document
/// order, duplicates included.
func topLevelMembers(_ text: String) throws -> [(String, JsonValue)] {
    var reader = JsonReader(bytes: Array(text.utf8))
    return try reader.objectMembers()
}

/// As ``topLevelMembers(_:)``, but the object must be the whole document:
/// only whitespace may follow it.
func wholeObjectMembers(_ text: String) throws -> [(String, JsonValue)] {
    var reader = JsonReader(bytes: Array(text.utf8))
    let members = try reader.objectMembers()
    try reader.skipWhitespace()
    guard reader.peek() == nil else { throw JsonError("content after the object") }
    return members
}

private struct JsonReader {
    let bytes: [UInt8]
    var at = 0
    var depth = 0

    func peek() -> UInt8? { at < bytes.count ? bytes[at] : nil }

    mutating func nextByte() throws -> UInt8 {
        guard let byte = peek() else { throw JsonError("unexpected end of input") }
        at += 1
        return byte
    }

    mutating func expect(_ wanted: UInt8) throws {
        guard try nextByte() == wanted else { throw JsonError("unexpected character") }
    }

    mutating func enter() throws {
        depth += 1
        if depth > maxJsonNestingDepth { throw JsonError("nesting deeper than 64") }
    }

    /// Space, tab, line feed and carriage return; any other control
    /// character outside a string is an error.
    mutating func skipWhitespace() throws {
        while let byte = peek() {
            switch byte {
            case 0x20, 0x09, 0x0A, 0x0D: at += 1
            case 0...0x1F: throw JsonError("illegal control character")
            default: return
            }
        }
    }

    mutating func objectMembers() throws -> [(String, JsonValue)] {
        try skipWhitespace()
        guard peek() == 0x7B else { throw JsonError("not a JSON object") }
        at += 1
        try enter()
        var members: [(String, JsonValue)] = []
        try skipWhitespace()
        if peek() == 0x7D {
            at += 1
            return members
        }
        while true {
            try skipWhitespace()
            let name = try self.name()
            try skipWhitespace()
            try expect(0x3A)  // ':'
            try skipWhitespace()
            let value = try topValue()
            members.append((name, value))
            try skipWhitespace()
            switch try nextByte() {
            case 0x2C: continue  // ','
            case 0x7D: return members  // '}'
            default: throw JsonError("expected ',' or '}'")
            }
        }
    }

    mutating func name() throws -> String {
        guard peek() == 0x22 else { throw JsonError("expected a member name") }
        let text = try string()
        guard text.utf16.count <= maxJsonNameLength else { throw JsonError("member name too long") }
        return text
    }

    mutating func topValue() throws -> JsonValue {
        switch peek() {
        case 0x22:  // '"'
            return .string(try string())
        case 0x5B:  // '['
            at += 1
            try enter()
            var strings: [String]? = []
            try skipWhitespace()
            if peek() == 0x5D {
                at += 1
            } else {
                elements: while true {
                    try skipWhitespace()
                    if peek() == 0x22 {
                        let text = try string()
                        strings?.append(text)
                    } else {
                        try skipValue()
                        strings = nil
                    }
                    try skipWhitespace()
                    switch try nextByte() {
                    case 0x2C: continue elements
                    case 0x5D: break elements
                    default: throw JsonError("expected ',' or ']'")
                    }
                }
            }
            depth -= 1
            return strings.map(JsonValue.strings) ?? .other
        case .some(let byte) where byte == 0x2D || (0x30...0x39).contains(byte):  // '-' '0'-'9'
            let start = at
            let integer = try number()
            let text = String(decoding: bytes[start..<at], as: UTF8.self)
            return .number(text: text, integer: integer)
        default:
            try skipValue()
            return .other
        }
    }

    mutating func skipValue() throws {
        switch peek() {
        case 0x22: _ = try string()
        case .some(let byte) where byte == 0x2D || (0x30...0x39).contains(byte): _ = try number()
        case 0x74: try literal([0x74, 0x72, 0x75, 0x65])  // true
        case 0x66: try literal([0x66, 0x61, 0x6C, 0x73, 0x65])  // false
        case 0x6E: try literal([0x6E, 0x75, 0x6C, 0x6C])  // null
        case 0x7B:  // '{'
            at += 1
            try enter()
            try skipWhitespace()
            if peek() == 0x7D {
                at += 1
            } else {
                members: while true {
                    try skipWhitespace()
                    _ = try name()
                    try skipWhitespace()
                    try expect(0x3A)
                    try skipWhitespace()
                    try skipValue()
                    try skipWhitespace()
                    switch try nextByte() {
                    case 0x2C: continue members
                    case 0x7D: break members
                    default: throw JsonError("expected ',' or '}'")
                    }
                }
            }
            depth -= 1
        case 0x5B:  // '['
            at += 1
            try enter()
            try skipWhitespace()
            if peek() == 0x5D {
                at += 1
            } else {
                elements: while true {
                    try skipWhitespace()
                    try skipValue()
                    try skipWhitespace()
                    switch try nextByte() {
                    case 0x2C: continue elements
                    case 0x5D: break elements
                    default: throw JsonError("expected ',' or ']'")
                    }
                }
            }
            depth -= 1
        case .some: throw JsonError("unexpected character")
        case nil: throw JsonError("unexpected end of input")
        }
    }

    /// `true`, `false` or `null`, not followed by another letter or digit.
    mutating func literal(_ word: [UInt8]) throws {
        let end = at + word.count
        guard end <= bytes.count, Array(bytes[at..<end]) == word else {
            throw JsonError("unrecognized token")
        }
        at = end
        if let next = peek(), isAlphanumericOrUnderscoreOrHighBit(next) {
            throw JsonError("unrecognized token")
        }
    }

    func isAlphanumericOrUnderscoreOrHighBit(_ byte: UInt8) -> Bool {
        (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5A)
            || (byte >= 0x61 && byte <= 0x7A) || byte == 0x5F || byte >= 0x80
    }

    /// Returns whether the number is an integer (no fraction or exponent).
    mutating func number() throws -> Bool {
        if peek() == 0x2D { at += 1 }  // '-'
        let intDigits = digits()
        switch intDigits {
        case 0: throw JsonError("expected a digit")
        case 1: break
        default:
            if bytes[at - intDigits] == 0x30 { throw JsonError("leading zeroes are not allowed") }
        }
        var total = intDigits
        var integer = true
        if peek() == 0x2E {  // '.'
            at += 1
            let fraction = digits()
            guard fraction != 0 else { throw JsonError("expected a digit after the decimal point") }
            total += fraction
            integer = false
        }
        if let byte = peek(), byte == 0x65 || byte == 0x45 {  // 'e' 'E'
            at += 1
            if let sign = peek(), sign == 0x2B || sign == 0x2D { at += 1 }
            let exponent = digits()
            guard exponent != 0 else { throw JsonError("expected a digit in the exponent") }
            total += exponent
            integer = false
        }
        let length = integer ? intDigits : total
        guard length <= maxJsonNumberLength else { throw JsonError("number too long") }
        return integer
    }

    mutating func digits() -> Int {
        let start = at
        while let byte = peek(), byte >= 0x30, byte <= 0x39 { at += 1 }
        return at - start
    }

    /// A string, unescaped; the reader stands on its opening quote.
    mutating func string() throws -> String {
        at += 1
        var out: [UInt8] = []
        var runStart = at
        while true {
            guard let byte = peek() else { throw JsonError("unterminated string") }
            switch byte {
            case 0x22:  // '"'
                out.append(contentsOf: bytes[runStart..<at])
                at += 1
                return String(decoding: out, as: UTF8.self)
            case 0x5C:  // '\\'
                out.append(contentsOf: bytes[runStart..<at])
                at += 1
                try escape(into: &out)
                runStart = at
            case 0...0x1F:
                throw JsonError("unescaped control character in string")
            default:
                at += 1
            }
        }
    }

    mutating func escape(into out: inout [UInt8]) throws {
        let byte = try nextByte()
        switch byte {
        case 0x22: out.append(0x22)  // '"'
        case 0x5C: out.append(0x5C)  // '\\'
        case 0x2F: out.append(0x2F)  // '/'
        case 0x62: out.append(0x08)  // 'b'
        case 0x66: out.append(0x0C)  // 'f'
        case 0x6E: out.append(0x0A)  // 'n'
        case 0x72: out.append(0x0D)  // 'r'
        case 0x74: out.append(0x09)  // 't'
        case 0x75:  // 'u'
            let unit = try hex4()
            var scalarValue = UInt32(unit)
            if (0xD800...0xDBFF).contains(unit), at + 1 < bytes.count, bytes[at] == 0x5C,
                bytes[at + 1] == 0x75
            {
                let saved = at
                at += 2
                let low = try hex4()
                if (0xDC00...0xDFFF).contains(low) {
                    scalarValue = 0x10000 + ((UInt32(unit) - 0xD800) << 10) + (UInt32(low) - 0xDC00)
                } else {
                    at = saved
                }
            }
            let scalar = Unicode.Scalar(scalarValue) ?? Unicode.Scalar(0xFFFD)!
            out.append(contentsOf: Array(String(scalar).utf8))
        default:
            throw JsonError("unrecognized escape")
        }
    }

    mutating func hex4() throws -> UInt32 {
        var value: UInt32 = 0
        for _ in 0..<4 {
            let byte = try nextByte()
            guard let digit = hexDigit(byte) else { throw JsonError("bad unicode escape") }
            value = value * 16 + digit
        }
        return value
    }

    func hexDigit(_ byte: UInt8) -> UInt32? {
        switch byte {
        case 0x30...0x39: return UInt32(byte - 0x30)
        case 0x41...0x46: return UInt32(byte - 0x41) + 10
        case 0x61...0x66: return UInt32(byte - 0x61) + 10
        default: return nil
        }
    }
}

/// A JSON number as epoch milliseconds: an integer must fit an `Int64`; a
/// number with a fraction or an exponent is read as a double and truncated
/// when it lies within the `Int64` range. Anything else, `1e300` say, is no
/// instant and is `nil`.
func jsonNumberAsInstant(text: String, integer: Bool) -> Int64? {
    if integer { return Int64(text) }
    guard let value = Double(text), value.isFinite else { return nil }
    let low = Double(Int64.min)
    let high = Double(Int64.max)
    guard value >= low, value <= high else { return nil }
    return Int64(value)
}
