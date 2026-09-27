import Foundation

/// The JSON writer for ``ReceiptPayload/toJson()`` and the endpoint's
/// response: objects written key by key. Ports agree on the value of
/// `toJson()`, not its bytes (docs/design/0.7-api.md "Our JSON"), so the
/// escaping below is one valid choice, not a cross-port contract.

/// A JSON object being written. `target` is
/// called with each fragment to append, in order — ordinarily a closure that
/// appends to the caller's `String` buffer, since Swift has no way to hold a
/// reference into a local `String` otherwise.
final class JsonObjectWriter {
    private var first = true
    private let _target: (String) -> Void

    private init(target: @escaping (String) -> Void) {
        self._target = target
        target("{")
    }

    static func open(into target: @escaping (String) -> Void) -> JsonObjectWriter {
        JsonObjectWriter(target: target)
    }

    func close() { _target("}") }

    func key(_ key: String) {
        if !first { _target(",") }
        first = false
        _target(quoteJson(key))
        _target(":")
    }

    func raw(_ text: String) { _target(text) }

    func string(_ key: String, _ value: String?) {
        self.key(key)
        _target(value.map(quoteJson) ?? "null")
    }

    func number(_ key: String, _ value: Int64?) {
        self.key(key)
        _target(value.map(String.init) ?? "null")
    }

    /// A 64-bit id, as a JSON string so JavaScript readers do not round it.
    func id(_ key: String, _ value: Int64?) {
        string(key, value.map(String.init))
    }

    func boolean(_ key: String, _ value: Bool?) {
        self.key(key)
        switch value {
        case .some(true): _target("true")
        case .some(false): _target("false")
        case nil: _target("null")
        }
    }

    func bytes(_ key: String, _ value: [UInt8]?) {
        string(key, value.map(standardBase64Encode))
    }

    func attributes(_ key: String, _ attributes: [Int: [[UInt8]]]) {
        self.key(key)
        _target("{")
        var innerFirst = true
        for type in attributes.keys.sorted() {
            if !innerFirst { _target(",") }
            innerFirst = false
            _target(quoteJson(String(type)))
            _target(":")
            _target("[")
            for (index, value) in (attributes[type] ?? []).enumerated() {
                if index > 0 { _target(",") }
                _target(quoteJson(standardBase64Encode(value)))
            }
            _target("]")
        }
        _target("}")
    }
}

/// A JSON string literal: `\"`, `\\` and the short escapes `\b \f \n \r \t`,
/// every other character below U+0020 as `\u00xx`, everything else raw.
func quoteJson(_ value: String) -> String {
    var out = "\""
    for scalar in value.unicodeScalars {
        switch scalar {
        case "\"": out += "\\\""
        case "\\": out += "\\\\"
        case "\u{8}": out += "\\b"
        case "\u{c}": out += "\\f"
        case "\n": out += "\\n"
        case "\r": out += "\\r"
        case "\t": out += "\\t"
        case "\u{0}"..."\u{1f}":
            out += String(format: "\\u%04x", scalar.value)
        default:
            out.unicodeScalars.append(scalar)
        }
    }
    out += "\""
    return out
}
