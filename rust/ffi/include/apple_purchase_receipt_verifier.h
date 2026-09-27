/*
 * apple-purchase-receipt-verifier — the C ABI.
 *
 * GENERATED FILE. Do not edit by hand: it is produced from rust/ffi/src/lib.rs
 * by cbindgen, committed, and re-generated in CI, which fails on any diff.
 *
 * Offline verification of Apple App Store JWS payloads and legacy PKCS#7 app
 * receipts against pinned Apple roots. Nothing here reads an operating-system
 * trust store and nothing here touches the network.
 *
 * OWNERSHIP, in one place:
 *
 *   - aprv_version() returns a static string. Never free it.
 *   - aprv_verifier_new() returns a handle the caller owns, or NULL if an
 *     argument was rejected. Release it with aprv_verifier_free().
 *     Freeing NULL is a no-op; freeing twice is undefined behaviour.
 *   - AprvResult.json and the *response_json of the endpoint call are owned
 *     by the caller. Release each with aprv_string_free() — never with the C
 *     runtime's free(), because the allocator is Rust's.
 *   - Every input pointer is borrowed for the duration of the call only.
 *     Nothing retains it, and nothing is written through it.
 *
 * THREADING: a handle is immutable once built. Any number of threads may
 * verify through the same handle concurrently; freeing one while a call is
 * in flight is not allowed.
 *
 * THE CLOCK: aprv_verifier_new takes one instant, in milliseconds since the
 * Unix epoch, instead of a callback the library would call back into. A NULL
 * clock pointer means the system clock. The clock is read in two places:
 * the certificate-validity instant when the input states no usable signing
 * date, and the endpoint's request_date. No verifier rejects a payload for
 * its age: how old a signed payload may be is the caller's decision.
 *
 * ERRORS: a NULL pointer, a non-UTF-8 string or a rejected configuration is
 * reported in the 100+ band of AprvReason and means nothing about the input
 * was checked. The 1..99 band is a verdict about the input. Never conflate
 * the two.
 *
 * JSON is the interchange because a verified payload is an open-ended claim
 * set that Apple extends at will; modelling it as C structs would make every
 * field Apple adds a breaking ABI change.
 */


#ifndef APPLE_PURCHASE_RECEIPT_VERIFIER_H
#define APPLE_PURCHASE_RECEIPT_VERIFIER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// The environment [`aprv_verify_receipt_endpoint`] answers as.
enum AprvEnvironment
#ifdef __cplusplus
  : uint32_t
#endif // __cplusplus
 {
  // `Production`
  APRV_ENVIRONMENT_PRODUCTION = 1,
  // `Sandbox`
  APRV_ENVIRONMENT_SANDBOX = 2,
};
#ifndef __cplusplus
typedef uint32_t AprvEnvironment;
#endif // __cplusplus

// The value of [`AprvResult::status`], and the return value of every
// verification call.
//
// Two bands, and the split is the point: `1..=99` is a **verdict about the
// input**, the canonical cross-port [`Reason`] vocabulary, while `100..` is
// a **mistake in the call itself**, where nothing about the input was
// checked. A caller that treats `APRV_REASON_NULL_POINTER` as "the receipt
// is forged" is reporting its own bug as an attack.
//
// **Stable and append-only.** These numbers are part of the ABI: a value is
// never reused for a different meaning and an existing value never changes.
// The 0.7 reason set kept the four codes whose meaning did not change and
// took new numbers for the rest. Retired and never reused: `1`
// (`INVALID_JWS_FORMAT`), `4` (`INVALID_CHAIN`), `6` to `10` (the 0.6
// policy and format reasons) and `11` (`STALE_PAYLOAD`).
enum AprvReason
#ifdef __cplusplus
  : int32_t
#endif // __cplusplus
 {
  // The call succeeded. `AprvResult::json` holds the payload.
  APRV_REASON_OK = 0,
  // A certificate cannot be used: it does not decode, or it is outside
  // its validity window at the chain instant.
  APRV_REASON_INVALID_CERTIFICATE = 2,
  // A certificate lacks the Apple marker OID for its place in the chain.
  APRV_REASON_INVALID_CERTIFICATE_PURPOSE = 3,
  // The signature did not verify.
  APRV_REASON_INVALID_SIGNATURE = 5,
  // Not the caller's fault: the library failed. Alert and reconcile; do
  // not deny the user on it.
  APRV_REASON_INTERNAL_ERROR = 12,
  // The base64, ASN.1, CMS or JWS structure is broken, or a structural
  // bound is exceeded.
  APRV_REASON_MALFORMED = 13,
  // The input is over a size cap and was not decoded.
  APRV_REASON_TOO_LARGE = 14,
  // The chain does not reach a pinned root.
  APRV_REASON_UNTRUSTED_CHAIN = 15,
  // A trusted signer signed content the library cannot read, found only
  // after the chain and the signature passed. Not the caller's fault.
  APRV_REASON_UNREADABLE_PAYLOAD = 16,
  // A required pointer argument was `NULL`. Nothing was verified.
  APRV_REASON_NULL_POINTER = 100,
  // A `const char *` argument was not valid UTF-8. Nothing was verified.
  APRV_REASON_INVALID_UTF8 = 101,
  // A configuration argument was rejected: an unknown environment, bytes
  // that are not a certificate, an anchor array that disagrees with its
  // count. Nothing was verified.
  APRV_REASON_INVALID_ARGUMENT = 102,
  // A panic was caught at the boundary. Nothing crossed it. This is a bug
  // in the library; please report it.
  APRV_REASON_PANIC = 103,
  // The library returned a verification reason this ABI has no code for,
  // which can only happen if the two are built from different versions.
  // Treat it as a rejection.
  APRV_REASON_UNKNOWN_REASON = 104,
};
#ifndef __cplusplus
typedef int32_t AprvReason;
#endif // __cplusplus

// A verifier: pinned roots and a clock. Created by `aprv_verifier_new`,
// released by `aprv_verifier_free`.
//
// Immutable once built, and safe to share between threads: any number of
// threads may verify through the same handle at the same time. Freeing it
// while another thread is inside a call is not.
typedef struct AprvVerifier AprvVerifier;

// The outcome of one verification call.
//
// `json` is owned by the caller and must be released with
// [`aprv_string_free`]. It is `NULL` only when the allocation itself could
// not be made.
//
// * `status == APRV_REASON_OK`: `json` is the verified payload, exactly
//   `ReceiptPayload::to_json()` for a receipt and the signed JSON text for
//   a JWS.
// * anything else: `json` is `{"reason":"<token>","message":"<detail>"}`.
//   The token is the `SCREAMING_SNAKE` spelling every port of this library
//   shares; the message is a short, non-sensitive description that never
//   contains receipt bytes, claims or key material. Match on `status`, or
//   on `reason`; never parse `message`.
typedef struct {
  // An [`AprvReason`] value.
  int32_t status;
  // Owned, NUL-terminated UTF-8 JSON. Free with [`aprv_string_free`].
  char *json;
} AprvResult;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// The library version, as a static NUL-terminated string. **Do not free
// it**, and do not assume it stays valid across a `dlclose`.
//
// It is the repository's own `version.txt`, the single file every port's
// version is bumped from, so it can never drift from the Rust library this
// ABI is compiled against.
const char *aprv_version(void);

// A verifier: the pinned roots and the clock.
//
// * `ders[i]` / `lens[i]` describe one DER trust anchor; the bytes are
//   parsed during the call and never retained. `NULL`, `NULL`, `0` selects
//   the three bundled Apple roots. A `count` of zero with either array
//   non-null is refused.
// * `fixed_clock_unix_millis`, when non-null, pins the clock at that
//   instant in milliseconds since the Unix epoch; `NULL` reads the system
//   clock on every call. A pointer rather than a sentinel value, because
//   every `int64_t` names a real instant.
//
// The clock is read once per call, in two places: the certificate-validity
// instant when the input states no usable signing date, and the endpoint's
// `request_date`. No payload is rejected for its age.
//
// Returns `NULL` if any argument is rejected. The handle is owned by the
// caller and must be released with [`aprv_verifier_free`].
//
// # Safety
// The three anchor arguments must describe `count` readable DER
// certificates, and `fixed_clock_unix_millis` must be `NULL` or point at
// one readable, aligned `int64_t`.
AprvVerifier *aprv_verifier_new(const uint8_t *const *ders,
                                const size_t *lens,
                                size_t count,
                                const int64_t *fixed_clock_unix_millis);

// Releases a handle from [`aprv_verifier_new`]. `NULL` is a no-op. Calling
// it twice on the same handle, or while another thread is inside a call on
// it, is undefined behaviour.
//
// # Safety
// `verifier` must be `NULL` or a live handle from [`aprv_verifier_new`].
void aprv_verifier_free(AprvVerifier *verifier);

// Verifies a legacy app receipt given as the base64 string an app sends.
// On success `out->json` is exactly `ReceiptPayload::to_json()`.
//
// Returns the status, which is also written to `out->status`. `out` may be
// `NULL` for a caller that only wants the status.
//
// # Safety
// `verifier` must be a live handle, `receipt_base64` a NUL-terminated
// string, and `out` `NULL` or a writable `AprvResult`.
int32_t aprv_verify_receipt(const AprvVerifier *verifier,
                            const char *receipt_base64,
                            AprvResult *out);

// Verifies any Apple-signed compact JWS: a transaction, a renewal info, an
// app transaction or a notification. On success `out->json` is the signed
// payload's JSON text, exactly as signed.
//
// # Safety
// As [`aprv_verify_receipt`], with `jws` for the input.
int32_t aprv_verify_signed_data(const AprvVerifier *verifier,
                                const char *jws,
                                AprvResult *out);

// Apple's `verifyReceipt`, answered locally: `request_json` is the request
// body, `*response_json` receives Apple's response body.
//
// `environment` is an [`AprvEnvironment`] value. Like Apple's endpoint this
// never reports a verification failure through the return value: every
// verdict is the `status` field **inside** the JSON. A non-zero return means
// the call itself was malformed (a null argument, a non-UTF-8 body, an
// unknown environment) and `*response_json` is then left untouched.
//
// `*response_json` is owned by the caller and must be released with
// [`aprv_string_free`].
//
// # Safety
// `verifier` must be a live handle, `request_json` a NUL-terminated
// string, and `response_json` a writable `char *`.
int32_t aprv_verify_receipt_endpoint(const AprvVerifier *verifier,
                                     uint32_t environment,
                                     const char *request_json,
                                     char **response_json);

// Releases a string this library handed out: an `AprvResult::json` or a
// `verifyReceipt` response body. `NULL` is a no-op. Never call it on
// [`aprv_version`]'s return value, and never free one of these with the C
// runtime's own `free`: the allocator is Rust's.
//
// # Safety
// `text` must be `NULL` or a string this library returned and that has not
// already been freed.
void aprv_string_free(char *text);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* APPLE_PURCHASE_RECEIPT_VERIFIER_H */
