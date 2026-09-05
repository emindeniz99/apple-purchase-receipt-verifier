import ApplePurchaseReceiptVerifier
import Foundation
import FuzzSupport

// `VerifyReceiptEndpoint.verifyReceiptJSON` — the one entry point that takes
// a request body rather than a receipt: JSON parse, `receipt-data`
// extraction, the receipt-base64 rule, the whole DER path, the 21007/21008
// environment routing, and finally the response rendering, which is where
// the receipt's own dates are formatted into Apple's three spellings.
//
// Its contract is stronger than the others': it never throws at all. Every
// body — any bytes at all — gets back a JSON object carrying a numeric
// `status`, and that is what is asserted after each call. A body that
// produced something else would be a response a caller's client could not
// parse, which for a drop-in replacement of Apple's endpoint is the failure
// that matters most.
//
// The anchor set is the pinned Apple receipt roots plus the generated
// fixture receipt root, so a seed carrying a real receipt reaches the
// status-0 branch and the date rendering under it, rather than stopping at
// 21003.

private let endpoint: VerifyReceiptEndpoint = {
    guard
        let endpoint = try? VerifyReceiptEndpoint(
            trustedRoots: appleReceiptRoots() + [Fixtures.receiptRoot],
            environment: .sandbox)
    else {
        fatalError("fuzz harness setup failed: the anchor set is not loadable")
    }
    return endpoint
}()

@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzEndpointJson(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt {
    guard let start else { return 0 }
    guard let body = fuzzText(start, count) else { return -1 }

    let response: String
    do {
        response = try blocking { await endpoint.verifyReceiptJSON(body) }
    } catch {
        fail("the endpoint, which is declared never to throw, threw \(error)")
    }

    // Decoded into a struct rather than inspected as `[String: Any]`.
    // JSONSerialization on Linux hands back an NSNumber for every JSON
    // number, and `NSNumber(0) is Bool` is TRUE there — the boolean bridge
    // makes 0 and 1 indistinguishable from `false` and `true`, so an
    // `is Bool` guard rejects the endpoint's own `"status":0`. A keyed
    // decode has neither problem: it requires a JSON object at the top
    // level, requires `status` to be present, and `Int` refuses both a
    // boolean and a non-integral number.
    guard let data = response.data(using: .utf8),
        (try? JSONDecoder().decode(EndpointResponse.self, from: data)) != nil
    else {
        fail(
            "the endpoint answered with something other than a JSON object "
                + "carrying a numeric status: \(response)")
    }
    return 0
}

private struct EndpointResponse: Decodable {
    let status: Int
}
