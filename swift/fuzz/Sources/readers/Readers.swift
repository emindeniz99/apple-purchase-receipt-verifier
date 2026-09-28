import Foundation
import FuzzSupport

// The readers this port writes by hand, driven on raw input rather than
// through a verifier. The ASN.1 tokenizer itself is swift-asn1's and is
// fuzzed upstream; what is hand-written here — and therefore what this
// target is for — is the glue on top of it.
//
// One execution drives both, because they take the same bytes from
// different angles and neither costs enough to be worth its own process.
// The third hand-written reader — the attribute-SET walk and the decoders
// under it — is the `receipt-payload` target instead, since its inputs are
// ASN.1 rather than text.
//
//  1. `decodeReceiptBase64` — the receipt transport rule: canonical standard
//     base64 and nothing else. Invariant:
//     an accepted string decodes to exactly as many bytes as its data
//     characters encode, so no padding rule can silently drop or invent one.
//  2. `base64URLDecode` — the compact-JWS segment rule, documented as strict
//     unpadded *canonical* base64url. Invariant: re-encoding an accepted
//     segment's bytes reproduces the segment character for character. That is
//     the canonicity claim restated independently, so a segment whose final
//     character carries non-zero unused bits has somewhere to fail.

@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzReaders(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt {
    guard let start else { return 0 }
    if let text = fuzzText(start, count) {
        checkReceiptBase64(text)
        checkBase64URL(text)
    }
    return 0
}

private func checkReceiptBase64(_ text: String) {
    guard let decoded = Readers.decodeReceiptBase64(text) else { return }
    // The data characters are the characters before the first `=`. Four of
    // them carry three bytes, and a trailing group of two or three carries
    // one or two.
    var characters = 0
    for byte in text.utf8 {
        if byte == 0x3D { break }  // '='
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
    let reencoded = Data(decoded).base64EncodedString()
        .replacingOccurrences(of: "=", with: "")
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
    guard reencoded == segment else {
        fail(
            "base64URLDecode accepted the non-canonical segment \(segment.debugDescription), "
                + "which re-encodes as \(reencoded.debugDescription)")
    }
}
