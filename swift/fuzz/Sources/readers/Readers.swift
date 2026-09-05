import Foundation
import FuzzSupport

// The readers this port writes by hand, driven on raw input rather than
// through a verifier. The ASN.1 tokenizer itself is swift-asn1's and is
// fuzzed upstream; what is hand-written here — and therefore what this
// target is for — is the glue on top of it.
//
// One execution drives all three, because they take the same bytes from
// different angles and none of them costs enough to be worth its own
// process. The fourth hand-written reader — the attribute-SET walk and the
// decoders under it — is the `receipt-payload` target instead: reaching it
// costs a chain build and an RSA verification per execution, and sharing an
// execution with these would drag them down to that rate for nothing.
//
//  1. `decodeReceiptBase64` — the receipt transport rule: whitespace
//     tolerated, exactly one alphabet, padding validated in place. Invariant:
//     an accepted string decodes to exactly as many bytes as its data
//     characters encode, so no padding rule can silently drop or invent one.
//  2. `base64URLDecode` — the compact-JWS segment rule, documented as strict
//     unpadded *canonical* base64url. Invariant: re-encoding an accepted
//     segment's bytes reproduces the segment character for character. That is
//     the canonicity claim restated independently, so a segment whose final
//     character carries non-zero unused bits has somewhere to fail.
//  3. `isRepresentableAsCertificateValidationTime` — the guard that keeps an
//     unverified date from reaching a certificate policy and trapping inside
//     X509's `Time`. Invariant: it answers `false` for every instant outside
//     the GeneralizedTime window, NaN and the infinities included.

@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzReaders(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt {
    guard let start else { return 0 }
    let bytes = fuzzInput(start, count)

    if let text = fuzzText(start, count) {
        checkReceiptBase64(text)
        checkBase64URL(text)
    }
    checkValidationTimeWindow(bytes)
    return 0
}

private func checkReceiptBase64(_ text: String) {
    guard let decoded = Readers.decodeReceiptBase64(text) else { return }
    // The data characters are the alphabet characters before the first `=`;
    // whitespace is skipped by the reader and skipped here for the same
    // reason. Four of them carry three bytes, and a trailing group of two or
    // three carries one or two.
    var characters = 0
    for byte in text.utf8 {
        if byte == 0x3D { break }  // '='
        if byte == 0x0D || byte == 0x0A || byte == 0x20 || byte == 0x09 { continue }
        characters += 1
    }
    let expected = characters / 4 * 3 + [0, 0, 1, 2][characters % 4]
    guard decoded.count == expected else {
        fail(
            "decodeReceiptBase64 turned \(characters) data characters into "
                + "\(decoded.count) bytes, expected \(expected)")
    }
}

private func checkBase64URL(_ segment: String) {
    guard let decoded = Readers.base64URLDecode(segment) else { return }
    let reencoded = decoded.base64EncodedString()
        .replacingOccurrences(of: "=", with: "")
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
    guard reencoded == segment else {
        fail(
            "base64URLDecode accepted the non-canonical segment \(segment.debugDescription), "
                + "which re-encodes as \(reencoded.debugDescription)")
    }
}

/// The window is 0001-01-01 to 9999-12-31 inclusive, in seconds since the
/// epoch. The input's first eight bytes are read as a raw `Double` bit
/// pattern so the fuzzer can steer at the boundaries — and at NaN and the
/// infinities — instead of only at instants a date string can spell.
private func checkValidationTimeWindow(_ bytes: [UInt8]) {
    guard bytes.count >= 8 else { return }
    let lower = -62_135_596_800.0
    let upper = 253_402_300_799.0
    let seconds = Double(bitPattern: bytes.prefix(8).reduce(UInt64(0)) { $0 << 8 | UInt64($1) })
    let answer = Readers.isRepresentableAsCertificateValidationTime(
        Date(timeIntervalSince1970: seconds))
    let expected = seconds >= lower && seconds <= upper
    guard answer == expected else {
        fail(
            "isRepresentableAsCertificateValidationTime answered \(answer) for "
                + "\(seconds) seconds since the epoch, expected \(expected)")
    }
}
