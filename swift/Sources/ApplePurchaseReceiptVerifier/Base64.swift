import Foundation

/// Base64, in the shapes this library needs.
///
/// ``decodeReceiptBase64(_:)`` is what `receipt-data`, the base64 string a
/// client actually sends, and every JWS `x5c` entry are decoded with:
/// canonical standard base64 and nothing else, the rule Apple's verifyReceipt
/// applies (measured 2026-09-23, see
/// `docs/evidence/2026-09-23-verifyreceipt-base64.md`) and the one RFC 7515
/// §4.1.6 gives an `x5c` entry.
///
/// ``decodeBase64URLStrict(_:)`` refuses anything that is not a canonical
/// RFC 4648 §5 encoding. The three segments of a compact JWS are decoded with
/// it, because there leniency is not convenience but malleability: a lenient
/// decoder lets an attacker who holds one Apple-signed `jwsRepresentation`
/// mint unboundedly many byte-distinct strings that all verify to the same
/// transaction. Strictness here goes one step past common platform decoders,
/// which accept a final character whose unused low bits are not zero.

/// Decodes `receipt-data` (or an `x5c` entry) by the rule Apple's
/// verifyReceipt applies: non-empty standard base64 (`[A-Za-z0-9+/]`)
/// carrying exactly the canonical `=` padding for its length, and nothing
/// else. Whitespace anywhere, base64url, omitted or extra padding and
/// anything after the padding are rejected (`nil`). Unused low bits in the
/// last data character are accepted, as Apple accepts them.
///
/// `Data(base64Encoded:)` alone is not the rule: on Linux
/// (swift-corelibs-foundation) it accepts over-padded input such as "AA===",
/// so the shape is checked first, byte by byte, and the decoder only ever
/// sees canonical input.
func decodeReceiptBase64(_ text: String) -> [UInt8]? {
    guard isCanonicalStandardBase64(text) else { return nil }
    guard let data = Data(base64Encoded: text) else { return nil }
    return [UInt8](data)
}

/// True when `text` is non-empty `[A-Za-z0-9+/]` data followed by the
/// canonical padding for its length and nothing else: total length a
/// multiple of four with at most two trailing `=`. Walks UTF-8 bytes rather
/// than `Character`s, which would fuse "\r\n" into one grapheme.
func isCanonicalStandardBase64(_ text: String) -> Bool {
    var count = 0
    var padding = 0
    for byte in text.utf8 {
        count += 1
        if byte == 0x3D {  // '='
            padding += 1
            continue
        }
        guard padding == 0 else { return false }
        switch byte {
        case 0x30...0x39, 0x41...0x5A, 0x61...0x7A, 0x2B, 0x2F:  // 0-9 A-Z a-z + /
            continue
        default:
            return false
        }
    }
    return count > 0 && count % 4 == 0 && padding <= 2
}

/// Standard base64 with padding.
func standardBase64Encode(_ bytes: [UInt8]) -> String {
    Data(bytes).base64EncodedString()
}

/// The compact-JWS segment alphabet (RFC 7515 §2): unpadded base64url.
private func base64URLValue(_ byte: UInt8) -> UInt32? {
    switch byte {
    case 0x41...0x5A: return UInt32(byte - 0x41)  // A-Z
    case 0x61...0x7A: return UInt32(byte - 0x61) + 26  // a-z
    case 0x30...0x39: return UInt32(byte - 0x30) + 52  // 0-9
    case 0x2D: return 62  // '-'
    case 0x5F: return 63  // '_'
    default: return nil
    }
}

/// Decodes unpadded base64url — RFC 4648 §5 as RFC 7515 §2 requires it — or
/// `nil`.
///
/// One byte sequence has exactly one encoding under this function, which is
/// the property the JWS path needs. Refused, where a lenient decoder would
/// accept: any byte outside `A-Z a-z 0-9 - _`; `=` anywhere at all — RFC 7515
/// §2 defines a JWS segment as base64url "with all trailing '=' characters
/// omitted"; a length that leaves one dangling character; or a final
/// character whose unused low bits are not zero.
func decodeBase64URLStrict(_ text: String) -> [UInt8]? {
    let bytes = Array(text.utf8)
    guard bytes.count % 4 != 1 else { return nil }
    var out: [UInt8] = []
    out.reserveCapacity(bytes.count / 4 * 3)
    var accumulator: UInt32 = 0
    var bits: UInt32 = 0
    for byte in bytes {
        guard let value = base64URLValue(byte) else { return nil }
        accumulator = (accumulator << 6) | value
        bits += 6
        if bits >= 8 {
            bits -= 8
            out.append(UInt8((accumulator >> bits) & 0xFF))
        }
    }
    if bits > 0, accumulator & ((1 << bits) - 1) != 0 { return nil }
    return out
}
