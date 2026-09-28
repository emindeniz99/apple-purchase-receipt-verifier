import ApplePurchaseReceiptVerifier
import Foundation
import FuzzSupport

// `Verifier.verifyReceiptEndpoint` — the one entry point that takes a
// request body rather than a receipt: the bounded JSON read, `receipt-data`
// extraction, the receipt-base64 rule, the whole DER path, the 21007/21008
// environment routing, and finally the response rendering, which is where
// the receipt's own dates are formatted into Apple's three spellings.
//
// Every body — any bytes at all — must get back a JSON object carrying a
// numeric `status` from the set the 0.7 status table can produce, and that
// is what is asserted after each call. A body that produced anything else
// would be a response a caller's client could not parse, which for a
// drop-in replacement of Apple's endpoint is the failure that matters most.
//
// The anchor set is the pinned Apple roots plus the 0.7 generated fixture
// receipt root, so a seed carrying a real receipt reaches the status-0
// branch and the date rendering under it, rather than stopping at 21003.

private let verifier = Fixtures.verifier(
    roots: Fixtures.appleRoots + [Fixtures.receiptRoot], what: "endpoint")

/// Every status the 0.7 endpoint answers with (docs/design/0.7-api.md,
/// "Status from Reason").
private let possibleStatuses: Set<Int> = [0, 21002, 21003, 21007, 21008, 21009]

@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzEndpointJson(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt {
    guard let start else { return 0 }
    guard let body = fuzzText(start, count) else { return -1 }
    let response = verifier.verifyReceiptEndpoint(environment: .sandbox, requestJson: body)

    // Decoded into a struct rather than inspected as `[String: Any]`.
    // JSONSerialization on Linux hands back an NSNumber for every JSON
    // number, and `NSNumber(0) is Bool` is TRUE there — the boolean bridge
    // makes 0 and 1 indistinguishable from `false` and `true`, so an
    // `is Bool` guard rejects the endpoint's own `"status":0`. A keyed
    // decode has neither problem: it requires a JSON object at the top
    // level, requires `status` to be present, and `Int` refuses both a
    // boolean and a non-integral number.
    guard let data = response.data(using: .utf8),
        let decoded = try? JSONDecoder().decode(EndpointResponse.self, from: data)
    else {
        fail(
            "the endpoint answered with something other than a JSON object "
                + "carrying a numeric status: \(response)")
    }
    guard possibleStatuses.contains(decoded.status) else {
        fail("the endpoint answered with status \(decoded.status), which no verdict maps to")
    }
    return 0
}

private struct EndpointResponse: Decodable {
    let status: Int
}
