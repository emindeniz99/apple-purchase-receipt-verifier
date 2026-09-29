/// The largest `receipt-data` string ``Verifier/verifyReceipt(base64:)``
/// reads, in UTF-8 bytes: Apple's own endpoint takes the same. Larger is
/// ``Reason/tooLarge``.
///
/// The three caps are public so a caller can size an HTTP body limit from
/// them. The verification module owns and applies them; this package adds
/// none of its own.
public let maxReceiptBytes = 3_145_728

/// The largest request body
/// ``Verifier/verifyReceiptEndpoint(environment:requestJson:)`` reads, in
/// UTF-8 bytes. Larger answers status 21002.
public let maxEndpointRequestBytes = 3_145_728

/// The largest compact JWS ``Verifier/verifySignedData(jws:)`` reads, in
/// UTF-8 bytes. Larger is ``Reason/tooLarge``.
public let maxJwsBytes = 262_144
