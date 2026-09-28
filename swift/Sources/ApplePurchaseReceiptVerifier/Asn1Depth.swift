/// The ASN.1 nesting bound, checked on the encoding before swift-asn1 builds
/// anything from it.
///
/// swift-asn1 has its own bound (`ASN1.ParserNode._maximumNodeDepth`, about
/// 49 values as the design counts them), looser than the shared one and not
/// this library's to choose. So the bound is enforced here, on the two
/// encodings a receipt carries — the CMS envelope, from its ContentInfo, and
/// the signed content, from its attribute SET — and counted as the design
/// and Java's `Asn1Depth` count it: at most ``maxAsn1Depth`` constructed
/// values inside one another, the outermost included, and a primitive value
/// inside the innermost.
///
/// The walk judges depth and nothing else. An encoding it cannot follow (a
/// truncated length, say) is not its verdict to give: it answers "not too
/// deep" and leaves the refusal to the parser that runs next.

/// At most this many constructed values inside one another.
let maxAsn1Depth = 32

/// Whether `der` nests more than ``maxAsn1Depth`` constructed values. BER
/// indefinite lengths are followed, since receipt envelopes use them.
func asn1DepthExceeded(_ der: [UInt8]) -> Bool {
    do {
        _ = try walkAsn1Depth(der, at: 0, end: der.count, depth: 0)
        return false
    } catch Asn1DepthWalk.tooDeep {
        return true
    } catch {
        return false
    }
}

private enum Asn1DepthWalk: Error {
    case tooDeep
    case unfollowable
}

/// Walks the value at `at`, below `depth` constructed values, and returns
/// where it ends. Recursion is bounded: a constructed value at depth
/// ``maxAsn1Depth`` stops the walk before it descends.
private func walkAsn1Depth(_ der: [UInt8], at: Int, end: Int, depth: Int) throws -> Int {
    guard at < end else { throw Asn1DepthWalk.unfollowable }
    let tag = der[at]
    var position = at + 1
    if tag & 0x1F == 0x1F {
        // A multi-byte tag number: continuation octets have the top bit set.
        while position < end, der[position] & 0x80 != 0 { position += 1 }
        position += 1
    }
    let constructed = tag & 0x20 != 0
    if constructed, depth >= maxAsn1Depth { throw Asn1DepthWalk.tooDeep }
    guard position < end else { throw Asn1DepthWalk.unfollowable }
    let first = der[position]
    position += 1
    if first == 0x80 {
        guard constructed else { throw Asn1DepthWalk.unfollowable }
        // Indefinite length: children until the end-of-contents octets.
        while true {
            if position + 1 < end, der[position] == 0, der[position + 1] == 0 { return position + 2 }
            position = try walkAsn1Depth(der, at: position, end: end, depth: depth + 1)
        }
    }
    var length = 0
    if first < 0x80 {
        length = Int(first)
    } else {
        let count = Int(first & 0x7F)
        guard count <= 4, position + count <= end else { throw Asn1DepthWalk.unfollowable }
        for _ in 0..<count {
            length = length << 8 | Int(der[position])
            position += 1
        }
    }
    guard length <= end - position else { throw Asn1DepthWalk.unfollowable }
    let contentEnd = position + length
    if constructed {
        while position < contentEnd {
            position = try walkAsn1Depth(der, at: position, end: contentEnd, depth: depth + 1)
        }
    }
    return contentEnd
}
