# Port parity

Which features each implementation ships. The nine ports are one product
(CONTRIBUTING.md), so a feature lands in every port or this table says why
not. [SUPPORT-MATRIX.md](./SUPPORT-MATRIX.md) covers a different question:
which language versions CI runs.

The C ABI in [`rust/ffi/`](rust/ffi/) wraps the Rust port. It inherits every
Rust verification decision; its column shows what the ABI exposes.

Checked against the code on `main`, 2026-09-22.

| Feature | Java | Node | Python | Go | Ruby | PHP | .NET | Rust | Swift | C ABI |
|---|---|---|---|---|---|---|---|---|---|---|
| Generic `ReceiptVerifier` (bundle id + device hash) | ✅ | ✅ both builds | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ `aprv_verify_receipt_*` |
| JWS verifier | ✅ | ✅ both builds | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ `aprv_verify_transaction` and 2 more |
| verifyReceipt-compatible endpoint | ✅ | ✅ both builds | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ JSON in, JSON out |
| `VerifyReceiptResult` with a verified flag | ✅ `isVerified()` | ✅ `verified` | ✅ `verified` | ✅ `Verified()` | ✅ `verified?` | ✅ `isVerified()` | ✅ `IsVerified` | ✅ `verified()` | ✅ `isVerified` | ❌ the ABI returns Apple's JSON only; use the generic verifier calls for a pass/fail answer |
| Re-render for the other environment (21007/21008 retry, no second verification) | ✅ `toJson(env)` | ✅ `toJson(env)`, `toResponse(env)` | ✅ `to_json(env)` | ✅ `JSONFor`, `ResponseFor` | ✅ `to_json(env)` | ✅ `toJson(env)` | ✅ `ToJson(env)` | ✅ `to_json_in` | ✅ `json(for:)` | ❌ no result handle crosses the ABI; call a second endpoint handle, which verifies again |
| Strict base64 fast path for `receipt-data` | ✅ `java.util.Base64.getDecoder()`, falls back on its exception | ✅ default build: `Buffer.from` behind a canonical-shape regex and `length % 4` check. ❌ web build: no `Buffer`, it runs the tolerant decoder only | ✅ `b64decode(validate=True)`, guarded by `len % 4 == 0`, no trailing `===`, non-empty | ✅ `base64.StdEncoding`, guarded by `DecodedLen <= limit` and a non-empty result | ✅ `unpack1("m0")`, guarded by non-empty input | ✅ `base64_decode($s, true)`, guarded by a non-empty result | ✅ net8.0: `Convert.TryFromBase64String` sized by `Base64.IsValid`. ❌ netstandard2.0: no `TryFromBase64String`, tolerant decoder only | ✅ `base64` crate `STANDARD`, guarded by non-empty input | ✅ `Data(base64Encoded:)` behind a byte-level canonical-shape check, since Foundation accepts over-padding on Linux | ✅ inherits Rust |
| Receipt cap, 2 MiB | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ inherits Rust |
| Request body cap, 1 MiB, and its unit | ✅ UTF-16 chars | ✅ UTF-8 bytes | ✅ chars for `str`, bytes for `bytes` | ✅ bytes | ✅ bytes (`bytesize`) | ✅ bytes (`strlen`) | ✅ UTF-16 chars | ✅ UTF-8 bytes | ✅ UTF-8 bytes | ✅ UTF-8 bytes, inherits Rust |
| JSON depth 64 (request body and JWS header/payload) | ✅ Jackson limit | ✅ | ✅ | ✅ | ✅ | ✅ `json_decode` depth | ✅ | ✅ | ✅ | ✅ inherits Rust |
| JWS cap, 256 KiB | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ inherits Rust |
| Fuzz target | ✅ `java-fuzz` | ✅ `node-fuzz`, default build | ✅ `python-fuzz` | ✅ `go-fuzz` | ✅ `ruby-fuzz` | ✅ `php-fuzz` | ✅ `dotnet-fuzz` | ✅ `rust-fuzz` | ✅ `swift-fuzz` | ❌ none of its own; `rust-fuzz` covers the parsers it calls, `cargo test` covers the ABI's edge cases |
| Tests in an optimized build | n/a, JIT | n/a | n/a | n/a, one build mode | n/a | n/a | ✅ `dotnet test -c Release` | ❌ `cargo test` runs the debug profile; no release leg yet | ✅ `swift test -c release`, Linux and macOS | ❌ tests run on a debug build; only the Elixir job builds release |
| Committed benchmark | ✅ `java-bench/` (JMH, on-demand workflow) | pending | pending | partial: `go/bench_test.go` has 5 benchmarks, no recorded baseline or workflow | pending | pending | pending | pending | pending | pending |
| Conformance suite (`fixtures/cases.json`) | ✅ | ✅ both builds | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ C++17 and ctypes harnesses |

Notes:

- The request cap constant is named `MAX_REQUEST_BYTES` (or `MaxRequestBytes`)
  in every port, but Java and .NET measure `String.length`, and Python
  measures a `str` in code points. A body of multi-byte characters can pass
  there and fail in the byte-counting ports. The contract does not pin the
  unit yet; see ROADMAP.md.
- The receipt cap applies twice: to the `receipt-data` string before it is
  decoded, and to the DER after.
- No endpoint checks the bundle id, as Apple's did not. Each port's README
  says so next to the endpoint.
