// Package applereceipt verifies Apple App Store purchase proofs offline.
//
// It covers both formats Apple ships:
//
//   - StoreKit 2 / App Store Server JWS payloads — signed transactions,
//     signed AppTransactions, renewal info and Server Notifications V2 —
//     through [Verifier.VerifySignedData].
//   - The legacy PKCS#7 app receipt, the exact blob apps used to send to
//     the deprecated verifyReceipt endpoint, through [Verifier.VerifyReceipt].
//
// [Verifier.VerifyReceiptEndpoint] answers Apple's verifyReceipt request bodies
// locally, with the same response shape and the same status codes.
//
// A [Verifier] answers one question: did Apple sign this data, under a
// pinned Apple root? If so, it returns the data. Bundle id, environment,
// product id, device binding, refunds and replay are the caller's checks;
// no method takes a parameter for any of them.
//
// # Trust model
//
// Verification is entirely offline and anchored only to the certificates
// in the [Config] — in production, the three published Apple roots that
// [AppleRoots] returns and [DefaultConfig] uses, compiled into the
// binary. The operating system trust store is never read. There is no
// OCSP, no CRL, no AIA fetch and no runtime root download: the module
// imports neither net nor net/http, and CI greps for the symbols that
// would reintroduce either (PLAN.md D12).
//
// Both paths additionally require Apple's marker OIDs: the leaf (on the
// receipt path, the signer) must carry 1.2.840.113635.100.6.11.1 and its
// intermediate 1.2.840.113635.100.6.2.1. Without those, any Apple
// developer's own certificate — which chains through the same WWDR
// intermediate to the same pinned root — could sign a fully forged
// receipt (PLAN.md D13).
//
// Certificate validity is judged at the instant the payload says it was
// signed: a JWS's signedDate, or a receipt's creation date (attribute 12).
// That is what lets a historical payload signed with a since-rotated
// certificate keep verifying. Only a payload with no usable date of its
// own is judged at the Config's clock.
//
// What signatures cannot tell you: a refund, a revocation or a renewal
// that happened after signing is invisible offline, and so is a replayed
// receipt. Track transaction ids server-side and use Apple's server API
// for current subscription state (INTENT.md).
//
// # Errors
//
// VerifyReceipt and VerifySignedData never panic. A failed verification
// returns a [*Failure] carrying one of the eight [Reason] constants and
// nothing else — no logging, no metrics, no callbacks (PLAN.md D11).
// Read it with errors.As, or with [ReasonOf]:
//
//	var failure *applereceipt.Failure
//	if errors.As(err, &failure) && failure.Reason == applereceipt.ReasonUntrustedChain {
//		alertSecurity()
//	}
//
// VerifyReceiptEndpoint returns no error at all: like Apple's endpoint,
// every failure is the status field of the response body.
//
// A configuration mistake — a nil Config, no trust anchors — is a plain
// error from [NewVerifier] instead, because misconfiguration is a
// programming bug and not a verdict about a receipt.
//
// # Concurrency
//
// A Verifier is immutable after construction and safe for concurrent use
// by multiple goroutines.
//
// # Example
//
//	verifier, err := applereceipt.NewVerifier(applereceipt.DefaultConfig())
//	if err != nil {
//		return err
//	}
//	payload, err := verifier.VerifySignedData(jws)
//	if err != nil {
//		return err // reject the purchase
//	}
//	// payload.JSON() is the signed payload exactly as Apple signed it:
//	// check bundleId, environment and productId yourself.
package applereceipt
