package applereceipt

// The bounds of docs/design/0.7-api.md, "Bounds". aprv.wasm's core owns and
// enforces every one of them; these constants only state them, so a caller
// can size a buffer or a test against them. The library adds no bound of
// its own.

// MaxReceiptBytes is the ceiling on receipt size: on the base64 string,
// in UTF-8 bytes, before it is decoded. It is 3 MiB, Apple's own limit,
// fixed and the same in every port of this library. Measured on
// 2026-09-23 against both of Apple's verifyReceipt endpoints, a request
// body of 3,145,728 bytes is answered and one of 3,145,729 bytes gets
// HTTP 413, and no receipt Apple accepts can be larger than the request
// that carries it.
const MaxReceiptBytes = 3_145_728

// MaxRequestBytes is the ceiling on a raw verifyReceipt request body, in
// UTF-8 bytes: 3 MiB, Apple's own limit, fixed and the same in every port
// of this library. Measured on 2026-09-23 against both of Apple's
// verifyReceipt endpoints, a body of 3,145,728 bytes is answered and one
// of 3,145,729 bytes gets HTTP 413. A larger body is StatusMalformedReceiptData,
// decided before the depth scan and before parsing.
const MaxRequestBytes = 3_145_728

// MaxJWSBytes bounds the compact JWS a verifier will look at, in UTF-8
// bytes, checked before the string is split or any segment decoded: a
// hostile multi-megabyte "JWS" is refused before it is base64-decoded and
// JSON-parsed. 256 KiB is the Java, PHP and Python ports' number; Apple's
// payloads are a few kilobytes.
const MaxJWSBytes = 262_144

// MaxJSONNestingDepth is how many arrays and objects a JWS header, a JWS
// payload or an endpoint request body may hold open at once, counted
// before the JSON is parsed (docs/design/0.7-api.md, Bounds).
const MaxJSONNestingDepth = 64

// MaxJSONMemberNameLength is how many characters a JSON object member
// name may hold, in a JWS header, a JWS payload or an endpoint request
// body, counted before the JSON is parsed (docs/design/0.7-api.md,
// Bounds). It bounds member NAMES only, never string values: a
// receipt-data or productId value of any length is unaffected.
const MaxJSONMemberNameLength = 50_000

// MaxJSONNumberDigits is how many digits a JSON number literal may hold,
// in the same three places, counted before the JSON is parsed
// (docs/design/0.7-api.md, Bounds).
const MaxJSONNumberDigits = 1_000
