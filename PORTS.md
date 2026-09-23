# Port parity

Which features each implementation ships. The nine ports are one product
(CONTRIBUTING.md), so a feature lands in every port or this table says why
not. [SUPPORT-MATRIX.md](./SUPPORT-MATRIX.md) covers a different question:
which language versions CI runs.

The C ABI in [`rust/ffi/`](rust/ffi/) wraps the Rust port. It inherits every
Rust verification decision; its column shows what the ABI exposes.

Checked against the code on `main`, 2026-09-23.

| Feature | Java | Node | Python | Go | Ruby | PHP | .NET | Rust | Swift | C ABI |
|---|---|---|---|---|---|---|---|---|---|---|
| Generic `ReceiptVerifier` (bundle id + device hash) | ✅ | ✅ both builds | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ `aprv_verify_receipt_*` |
| JWS verifier | ✅ | ✅ both builds | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ `aprv_verify_transaction` and 2 more |
| verifyReceipt-compatible endpoint | ✅ | ✅ both builds | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ JSON in, JSON out |
| `VerifyReceiptResult` with a verified flag | ✅ `isVerified()` | ✅ `verified` | ✅ `verified` | ✅ `Verified()` | ✅ `verified?` | ✅ `isVerified()` | ✅ `IsVerified` | ✅ `verified()` | ✅ `isVerified` | ❌ the ABI returns Apple's JSON only; use the generic verifier calls for a pass/fail answer |
| Re-render for the other environment (21007/21008 retry, no second verification) | ✅ `toJson(env)` | ✅ `toJson(env)`, `toResponse(env)` | ✅ `to_json(env)` | ✅ `JSONFor`, `ResponseFor` | ✅ `to_json(env)` | ✅ `toJson(env)` | ✅ `ToJson(env)` | ✅ `to_json_in` | ✅ `json(for:)` | ❌ no result handle crosses the ABI; call a second endpoint handle, which verifies again |
| `receipt-data` and `x5c` decoder: canonical standard base64 only, as Apple measures it | ✅ `Base64.getDecoder()` behind a `length % 4` check | ✅ `Buffer.from` behind a canonical-shape regex and `length % 4` check; web build: the shared decoder behind the same check | ✅ `b64decode(validate=True)` behind a shape regex and `len % 4` | ✅ `base64.StdEncoding` behind a byte-level shape check (it skips CR and LF) | ✅ `unpack1("m")` behind a `String#count` shape check (`"m0"` refuses the trailing bits Apple accepts) | ✅ `base64_decode($s, true)` behind `strspn` and `length % 4` | ✅ `Convert.FromBase64String` behind a shape check, both builds | ✅ `base64` crate engine with `decode_allow_trailing_bits`, non-empty | ✅ `Data(base64Encoded:)` behind a byte-level canonical-shape check, since Foundation accepts over-padding on Linux | ✅ inherits Rust |
| Receipt cap, 3,145,728 bytes, fixed | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ inherits Rust |
| Request body cap, 3,145,728 UTF-8 bytes, fixed, and how it is counted | ✅ `Utf8Length`, walks the string only between two length shortcuts | ✅ `utf8LengthExceeds`, same shortcuts, both builds | ✅ `utf8_exceeds`: length shortcuts, then encodes a non-ASCII `str` (`surrogatepass`); `len` of `bytes` | ✅ `len` of `[]byte` | ✅ `bytesize` | ✅ `strlen` | ✅ `Utf8Length.Exceeds`, same shortcuts | ✅ `str::len` | ✅ `utf8.count` | ✅ bytes, inherits Rust |
| `REQUEST_TOO_LARGE` for a body over the cap (result-only, status 21002) | ✅ `Reason.REQUEST_TOO_LARGE` | ✅ `Reason.REQUEST_TOO_LARGE` | ✅ `Reason.REQUEST_TOO_LARGE` | ✅ `ReasonRequestTooLarge` | ✅ `Reason::REQUEST_TOO_LARGE` | ✅ `Reason::RequestTooLarge` | ✅ `VerificationReason.RequestTooLarge` | ✅ `Reason::RequestTooLarge` | ✅ `.requestTooLarge` | ❌ the ABI returns Apple's JSON only, `{"status":21002}` |
| JSON depth 64 (request body and JWS header/payload) | ✅ Jackson limit | ✅ | ✅ | ✅ | ✅ | ✅ `json_decode` depth | ✅ | ✅ | ✅ | ✅ inherits Rust |
| JWS cap, 256 KiB | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ inherits Rust |
| Fuzz target | ✅ `java-fuzz` | ✅ `node-fuzz`, default build | ✅ `python-fuzz` | ✅ `go-fuzz` | ✅ `ruby-fuzz` | ✅ `php-fuzz` | ✅ `dotnet-fuzz` | ✅ `rust-fuzz` | ✅ `swift-fuzz` | ❌ none of its own; `rust-fuzz` covers the parsers it calls, `cargo test` covers the ABI's edge cases |
| Tests in an optimized build | n/a, JIT | n/a | n/a | n/a, one build mode | n/a | n/a | ✅ `dotnet test -c Release` | ❌ `cargo test` runs the debug profile; no release leg yet | ✅ `swift test -c release`, Linux and macOS | ❌ tests run on a debug build; only the Elixir job builds release |
| Committed benchmark | ✅ `java-bench/` (JMH, on-demand workflow) | pending | pending | partial: `go/bench_test.go` has 5 benchmarks, no recorded baseline or workflow | pending | pending | pending | pending | pending | pending |
| Conformance suite (`fixtures/cases.json`) | ✅ | ✅ both builds | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ C++17 and ctypes harnesses |

Notes:

- Both caps are Apple's: 3,145,728 bytes answered, 3,145,729 refused with
  HTTP 413, counted in UTF-8 bytes (measured 2026-09-23, COMPARISON.md).
  `fixtures/cases.json` pins them as a MUST. The request cap constant is
  `MAX_REQUEST_BYTES` (or `MaxRequestBytes`) in every port, and no caller
  can change either cap.
- A lone surrogate has no UTF-8 encoding; ports may count it differently.
  No vector contains one.
- The receipt cap applies twice: to the `receipt-data` string before it is
  decoded, and to the DER after.
- No endpoint checks the bundle id, as Apple's did not. Each port's README
  says so next to the endpoint.
