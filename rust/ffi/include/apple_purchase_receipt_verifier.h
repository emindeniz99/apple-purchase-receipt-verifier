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
 *   - Every aprv_*_new*() returns a handle the caller owns, or NULL if an
 *     argument was rejected. Release it with the matching aprv_*_free().
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
 * ERRORS: a NULL pointer, a non-UTF-8 string or a rejected configuration is
 * reported in the 100+ band of AprvReason and means nothing about the input
 * was checked. The 1..11 band is a verdict about the input. Never conflate
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

// The four App Store environments, as bits of the `accepted_environments`
// mask. OR them together; `0` is rejected.
enum AprvEnvironment
#ifdef __cplusplus
  : uint32_t
#endif // __cplusplus
 {
  // `Production`
  APRV_ENVIRONMENT_PRODUCTION = 1,
  // `Sandbox`
  APRV_ENVIRONMENT_SANDBOX = 2,
  // `Xcode` — `StoreKit` Testing in Xcode; not Apple-signed.
  APRV_ENVIRONMENT_XCODE = 4,
  // `LocalTesting` — `StoreKit` Test in a simulator.
  APRV_ENVIRONMENT_LOCAL_TESTING = 8,
};
#ifndef __cplusplus
typedef uint32_t AprvEnvironment;
#endif // __cplusplus

// The value of [`AprvResult::status`], and the return value of every
// verification call.
//
// Two bands, and the split is the point: `1..=11` is a **verdict about the
// input** — the canonical cross-port [`Reason`] vocabulary, in the order
// `Reason` declares it — while `100..` is a **mistake in the call itself**,
// where nothing about the input was checked. A caller that treats
// `APRV_REASON_NULL_POINTER` as "the receipt is forged" is reporting its own
// bug as an attack.
//
// **Stable and append-only.** These numbers are part of the ABI: a value is
// never reused for a different meaning and an existing value never changes.
// A twelfth verification reason — which the cross-port contract makes a
// deliberate, all-nine-ports change — would be 12.
enum AprvReason
#ifdef __cplusplus
  : int32_t
#endif // __cplusplus
 {
  // The call succeeded. `AprvResult::json` holds the payload.
  APRV_REASON_OK = 0,
  // The compact JWS is not three base64url segments of the right shape.
  APRV_REASON_INVALID_JWS_FORMAT = 1,
  // An `x5c` entry is not a parseable X.509 certificate.
  APRV_REASON_INVALID_CERTIFICATE = 2,
  // A certificate lacks the Apple marker OID for this purpose.
  APRV_REASON_INVALID_CERTIFICATE_PURPOSE = 3,
  // The path does not reach a pinned anchor, or was not valid then.
  APRV_REASON_INVALID_CHAIN = 4,
  // The signature did not verify.
  APRV_REASON_INVALID_SIGNATURE = 5,
  // The verified payload names a different bundle id.
  APRV_REASON_WRONG_BUNDLE_ID = 6,
  // The verified environment is outside the accepted set.
  APRV_REASON_WRONG_ENVIRONMENT = 7,
  // A Production `AppTransaction` names a different app Apple id.
  APRV_REASON_WRONG_APP_APPLE_ID = 8,
  // The legacy PKCS#7 receipt could not be parsed.
  APRV_REASON_INVALID_RECEIPT_FORMAT = 9,
  // `SHA1(guid || opaqueValue || bundleIdBytes)` does not match.
  APRV_REASON_DEVICE_HASH_MISMATCH = 10,
  // The payload was signed longer ago than the configured maximum.
  APRV_REASON_STALE_PAYLOAD = 11,
  // A required pointer argument was `NULL`. Nothing was verified.
  APRV_REASON_NULL_POINTER = 100,
  // A `const char *` argument was not valid UTF-8. Nothing was verified.
  APRV_REASON_INVALID_UTF8 = 101,
  // A configuration argument was rejected — an empty bundle id, an empty
  // or unknown environment mask, no trust anchors, bytes that are not a
  // certificate. Nothing was verified.
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

// A verifier for Apple-signed JWS payloads. Created by
// `aprv_verifier_new_jws`, released by `aprv_verifier_free_jws`.
//
// Immutable once built, and safe to share between threads: any number of
// threads may verify through the same handle at the same time. Freeing it
// while another thread is inside a call is not.
typedef struct AprvJwsVerifier AprvJwsVerifier;

// The local `verifyReceipt` endpoint. Same thread-safety rule as
// [`AprvJwsVerifier`].
typedef struct AprvReceiptEndpoint AprvReceiptEndpoint;

// A verifier for legacy PKCS#7 app receipts. Same thread-safety rule as
// [`AprvJwsVerifier`].
typedef struct AprvReceiptVerifier AprvReceiptVerifier;

// The outcome of one verification call.
//
// `json` is owned by the caller and must be released with
// [`aprv_string_free`]. It is `NULL` only when the allocation itself could
// not be made.
//
// * `status == APRV_REASON_OK` — `json` is the verified payload: the claim
//   object for the JWS calls, the normalised receipt object for the receipt
//   calls.
// * anything else — `json` is `{"reason":"<token>","message":"<detail>"}`.
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

// A JWS verifier pinned to the three bundled Apple roots.
//
// * `bundle_id` — required, non-empty.
// * `accepted_environments` — a non-zero OR of [`AprvEnvironment`] bits.
// * `app_apple_id` — `0` means "not configured"; required to accept a
//   Production `AppTransaction`.
// * `max_signed_age_secs` — `0` means "no staleness rule".
//
// Returns `NULL` if any argument is rejected. The handle is owned by the
// caller and must be released with [`aprv_verifier_free_jws`].
//
// # Safety
// `bundle_id` must be `NULL` or a NUL-terminated UTF-8 string.
AprvJwsVerifier *aprv_verifier_new_jws(const char *bundle_id,
                                       uint32_t accepted_environments,
                                       uint64_t app_apple_id,
                                       uint64_t max_signed_age_secs);

// [`aprv_verifier_new_jws`] with caller-supplied DER trust anchors.
//
// `ders[i]` / `lens[i]` describe one DER certificate; `count` must be
// non-zero. Nothing is retained: the bytes are parsed during the call.
//
// # Safety
// `bundle_id` must be `NULL` or a NUL-terminated UTF-8 string, and the
// three anchor arguments must describe `count` readable DER certificates.
AprvJwsVerifier *aprv_verifier_new_jws_with_roots(const char *bundle_id,
                                                  uint32_t accepted_environments,
                                                  uint64_t app_apple_id,
                                                  uint64_t max_signed_age_secs,
                                                  const uint8_t *const *ders,
                                                  const size_t *lens,
                                                  size_t count);

// Releases a handle from `aprv_verifier_new_jws*`. `NULL` is a no-op.
// Calling it twice on the same handle, or while another thread is inside a
// verification call on it, is undefined behaviour.
//
// # Safety
// `verifier` must be `NULL` or a handle this library returned and that has
// not been freed.
void aprv_verifier_free_jws(AprvJwsVerifier *verifier);

// A legacy-receipt verifier pinned to the three bundled Apple roots.
// Returns `NULL` if `bundle_id` is null, not UTF-8, or empty.
//
// # Safety
// `bundle_id` must be `NULL` or a NUL-terminated UTF-8 string.
AprvReceiptVerifier *aprv_verifier_new_receipt(const char *bundle_id);

// [`aprv_verifier_new_receipt`] with caller-supplied DER trust anchors.
//
// # Safety
// As [`aprv_verifier_new_jws_with_roots`].
AprvReceiptVerifier *aprv_verifier_new_receipt_with_roots(const char *bundle_id,
                                                          const uint8_t *const *ders,
                                                          const size_t *lens,
                                                          size_t count);

// Releases a handle from `aprv_verifier_new_receipt*`. `NULL` is a no-op.
//
// # Safety
// As [`aprv_verifier_free_jws`].
void aprv_verifier_free_receipt(AprvReceiptVerifier *verifier);

// A local `verifyReceipt` endpoint pinned to the bundled Apple roots.
//
// `environment` is exactly one of `APRV_ENVIRONMENT_PRODUCTION` or
// `APRV_ENVIRONMENT_SANDBOX` — Apple's endpoint has two, and the choice is
// what drives the local 21007/21008 routing. Anything else returns `NULL`.
//
// # Safety
// This function dereferences nothing; it is `unsafe` only for symmetry with
// the variant that takes anchors.
AprvReceiptEndpoint *aprv_endpoint_new(uint32_t environment);

// [`aprv_endpoint_new`] with caller-supplied DER trust anchors.
//
// # Safety
// As [`aprv_verifier_new_jws_with_roots`].
AprvReceiptEndpoint *aprv_endpoint_new_with_roots(uint32_t environment,
                                                  const uint8_t *const *ders,
                                                  const size_t *lens,
                                                  size_t count);

// Releases a handle from `aprv_endpoint_new*`. `NULL` is a no-op.
//
// # Safety
// As [`aprv_verifier_free_jws`].
void aprv_endpoint_free(AprvReceiptEndpoint *endpoint);

// Verifies a signed transaction, then checks bundle id and environment.
//
// On success `out->json` is the claim object, with Apple's own claim names
// and Apple's own date spelling (epoch milliseconds).
//
// # Safety
// `verifier` must be a live handle, `jws` a NUL-terminated string, and
// `out` a writable `AprvResult`. Any of them may be `NULL`, which is
// reported rather than dereferenced.
int32_t aprv_verify_transaction(const AprvJwsVerifier *verifier,
                                const char *jws,
                                AprvResult *out);

// Verifies a signed `AppTransaction`, then checks bundle id, environment
// (`receiptType`) and — in Production — the app Apple id.
//
// # Safety
// As [`aprv_verify_transaction`].
int32_t aprv_verify_app_transaction(const AprvJwsVerifier *verifier,
                                    const char *jws,
                                    AprvResult *out);

// Verifies the certificate chain and signature only, and returns every
// claim. **No claim is enforced** — for renewal info and notification
// envelopes, where the caller must check bundle id, environment and app
// Apple id itself.
//
// # Safety
// As [`aprv_verify_transaction`].
int32_t aprv_verify_raw(const AprvJwsVerifier *verifier,
                        const char *jws,
                        AprvResult *out);

// Verifies a legacy PKCS#7 app receipt in its raw DER form.
//
// On success `out->json` is the normalised receipt object: dates as
// ISO-8601 UTC strings, byte attributes as lowercase hex (mirrored under
// `<name>Hex`), `unknownAttributes` keyed by the attribute number.
//
// # Safety
// `verifier` must be a live handle and `der`/`len` must describe `len`
// readable bytes. `out` must be writable or `NULL`.
int32_t aprv_verify_receipt_der(const AprvReceiptVerifier *verifier,
                                const uint8_t *der,
                                size_t len,
                                AprvResult *out);

// [`aprv_verify_receipt_der`] that also checks the SHA-1 device hash
// against `guid`/`guid_len` — attribute 5 must equal
// `SHA1(guid || opaqueValue || bundleIdBytes)`, or the call fails with
// `APRV_REASON_DEVICE_HASH_MISMATCH`.
//
// # Safety
// As [`aprv_verify_receipt_der`], plus `guid`/`guid_len` describing
// `guid_len` readable bytes.
int32_t aprv_verify_receipt_der_with_device_guid(const AprvReceiptVerifier *verifier,
                                                 const uint8_t *der,
                                                 size_t len,
                                                 const uint8_t *guid,
                                                 size_t guid_len,
                                                 AprvResult *out);

// Verifies a legacy app receipt given as the base64 string a client sends.
//
// # Safety
// `verifier` must be a live handle and `receipt_base64` a NUL-terminated
// string. `out` must be writable or `NULL`.
int32_t aprv_verify_receipt_base64(const AprvReceiptVerifier *verifier,
                                   const char *receipt_base64,
                                   AprvResult *out);

// [`aprv_verify_receipt_base64`] with the SHA-1 device-hash check.
//
// # Safety
// As [`aprv_verify_receipt_base64`], plus `guid`/`guid_len` describing
// `guid_len` readable bytes.
int32_t aprv_verify_receipt_base64_with_device_guid(const AprvReceiptVerifier *verifier,
                                                    const char *receipt_base64,
                                                    const uint8_t *guid,
                                                    size_t guid_len,
                                                    AprvResult *out);

// Handles one `verifyReceipt` request body and writes Apple's response body
// to `*response_json`.
//
// Like Apple's endpoint this never reports a verification failure through
// the return value: every verdict is the `status` field **inside** the JSON.
// A non-zero return means the call itself was malformed — a null argument,
// a non-UTF-8 body — and `*response_json` is then left untouched.
//
// `*response_json` is owned by the caller and must be released with
// [`aprv_string_free`].
//
// # Safety
// `endpoint` must be a live handle, `request_json` a NUL-terminated string,
// and `response_json` a writable `char *`.
int32_t aprv_verify_receipt_endpoint_json(const AprvReceiptEndpoint *endpoint,
                                          const char *request_json,
                                          char **response_json);

// Releases a string this library handed out — an `AprvResult::json` or a
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
