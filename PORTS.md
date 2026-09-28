# Port parity

Which features each implementation ships. The nine ports are one product
(CONTRIBUTING.md), so a feature lands in every port or this table says why
not. [SUPPORT-MATRIX.md](./SUPPORT-MATRIX.md) covers a different question:
which language versions CI runs.

The C ABI in [`rust/ffi/`](rust/ffi/) wraps the Rust port. It inherits every
Rust verification decision; its column shows what the ABI exposes.

Checked against the code on `feat/0.7-verifier-api`, 2026-09-27.

| Feature | Java | Node | Python | Go | Ruby | PHP | .NET | Rust | Swift | C ABI |
|---|---|---|---|---|---|---|---|---|---|---|
| One `Verifier` with `verifyReceipt`, `verifySignedData` and `verifyReceiptEndpoint`, built from a `Config` (roots, clock) | ✅ | ✅ both builds | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ `aprv_verifier_new`, `aprv_verify_receipt`, `aprv_verify_signed_data`, `aprv_verify_receipt_endpoint` |
| Result form | `VerificationResult` | result object | result object | `(payload, error)` | result object | result object | result object | `Result<Payload, Failure>` | `VerificationResult` | JSON document |
| Clock | `java.time.Clock` | `() => number` | callable | `func() int64` | proc | PSR-20 `ClockInterface` | `Func<long>` | closure returning epoch ms | closure | a fixed instant in ms, or `NULL` for the system clock |
| No bundle id, environment, app Apple id or device id parameter | ✅ | ✅ both builds | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| JWS payload returned as the JSON Apple signed, read only for `signedDate` | ✅ | ✅ both builds | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ inherits Rust |
| `receipt-data` and `x5c` decoder: canonical standard base64 only, as Apple measures it | ✅ `Base64.getDecoder()` behind a `length % 4` check | ✅ `Buffer.from` behind a canonical-shape regex and `length % 4` check; web build: the shared decoder behind the same check | ✅ `b64decode(validate=True)` behind a shape regex and `len % 4` | ✅ `base64.StdEncoding` behind a byte-level shape check (it skips CR and LF) | ✅ `unpack1("m")` behind a `String#count` shape check (`"m0"` refuses the trailing bits Apple accepts) | ✅ `base64_decode($s, true)` behind `strspn` and `length % 4` | ✅ `Convert.FromBase64String` behind a shape check, both builds | ✅ `base64` crate engine with `decode_allow_trailing_bits`, non-empty | ✅ `Data(base64Encoded:)` behind a byte-level canonical-shape check, since Foundation accepts over-padding on Linux | ✅ inherits Rust |
| Receipt cap, 3,145,728 UTF-8 bytes of base64, fixed | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ inherits Rust |
| Request body cap, 3,145,728 UTF-8 bytes, fixed, and how it is counted | ✅ `Utf8Length`, walks the string only between two length shortcuts | ✅ `utf8LengthExceeds`, same shortcuts, both builds | ✅ `utf8_exceeds`: length shortcuts, then encodes a non-ASCII `str` (`surrogatepass`); `len` of `bytes` | ✅ `len` of `[]byte` | ✅ `bytesize` | ✅ `strlen` | ✅ `Utf8Length.Exceeds`, same shortcuts | ✅ `str::len` | ✅ `utf8.count` | ✅ bytes, inherits Rust |
| `TOO_LARGE` for any input over its cap (status 21002 at the endpoint) | ✅ `Reason.TOO_LARGE` | ✅ `Reason.TOO_LARGE` | ✅ `Reason.TOO_LARGE` | ✅ `ReasonTooLarge` | ✅ `Reason::TOO_LARGE` | ✅ `Reason::TooLarge` | ✅ `VerificationReason.TooLarge` | ✅ `Reason::TooLarge` | ✅ `.tooLarge` | ✅ inherits Rust; the endpoint answers `{"status":21002}` |
| Legacy receipt order: CMS, creation date only, chain, markers, signature, full parse; signed content that does not parse is `UNREADABLE_PAYLOAD` (21009) | ✅ | ✅ both builds | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ inherits Rust |
| ASN.1 depth 32, at most 4 SignerInfos and 10 embedded certificates | ✅ | ✅ both builds | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ inherits Rust |
| Chain walked top-down from the pinned roots; a stranger certificate is ignored (#161) | ✅ | ✅ both builds | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ inherits Rust |
| JSON depth 64 (request body and JWS header/payload) | ✅ Jackson limit | ✅ | ✅ | ✅ | ✅ | ✅ `json_decode` depth | ✅ | ✅ | ✅ | ✅ inherits Rust |
| JWS cap, 256 KiB | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ inherits Rust |
| Fuzz target | ✅ `java-fuzz` | ✅ `node-fuzz`, default build | ✅ `python-fuzz` | ✅ `go-fuzz` | ✅ `ruby-fuzz` | ✅ `php-fuzz` | ✅ `dotnet-fuzz` | ✅ `rust-fuzz` | ✅ `swift-fuzz` | ❌ none of its own; `rust-fuzz` covers the parsers it calls, `cargo test` covers the ABI's edge cases |
| Tests in an optimized build | n/a, JIT | n/a | n/a | n/a, one build mode | n/a | n/a | ✅ `dotnet test -c Release` | ❌ `cargo test` runs the debug profile; no release leg yet | ✅ `swift test -c release`, Linux and macOS | ❌ tests run on a debug build; only the Elixir job builds release |
| Committed benchmark | ✅ `java-bench/` (JMH, on-demand workflow) | pending | pending | partial: `go/bench_test.go` has 5 benchmarks, no recorded baseline or workflow | pending | pending | pending | pending | pending | pending |
| Conformance suite (`fixtures/cases.json`) | ✅ | ✅ both builds | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ C++17 and ctypes harnesses, except the `decodeBase64` groups: the ABI exposes no base64 decoder, so they are counted as not reachable |

Notes:

- Both caps are Apple's: 3,145,728 bytes answered, 3,145,729 refused with
  HTTP 413, counted in UTF-8 bytes (measured 2026-09-23, COMPARISON.md).
  `fixtures/cases.json` pins them as a MUST, and no caller can change
  either cap.
- A lone surrogate has no UTF-8 encoding; ports may count it differently.
  No vector contains one.
- The `decodeBase64` conformance groups call each port's `receipt-data`
  and `x5c` decoders directly, through the port's usual internal access.
  Every runner also asserts that every case id in `cases.json` ran.
- The receipt cap applies to the base64 string, before it is decoded;
  0.7 takes no DER, so there is no second cap on the decoded bytes.
- Nothing checks the bundle id, the endpoint included, as Apple's did not.
  Each port's README lists the checks that stay with the caller.
