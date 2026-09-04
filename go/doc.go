// Package applereceipt verifies Apple App Store purchase proofs offline.
//
// It covers both formats Apple ships:
//
//   - StoreKit 2 / App Store Server JWS payloads — signed transactions,
//     signed AppTransactions, renewal info and Server Notifications V2 —
//     through [JWSVerifier].
//   - The legacy PKCS#7 app receipt, the exact blob apps used to send to
//     the deprecated verifyReceipt endpoint, through [ReceiptVerifier].
//
// [VerifyReceiptEndpoint] answers Apple's verifyReceipt request bodies
// locally, with the same response shape and the same status codes.
//
// # Trust model
//
// Verification is entirely offline and anchored only to certificates the
// caller passes in — in production, the three published Apple roots that
// [AppleJWSRoots] and [AppleReceiptRoots] return, compiled into the
// binary. The operating system trust store is never read. There is no
// OCSP, no CRL, no AIA fetch and no runtime root download: the module
// imports neither net nor net/http, and CI greps for the symbols that
// would reintroduce either (PLAN.md D12).
//
// Both paths additionally require Apple's marker OIDs. On the JWS path
// the leaf must carry 1.2.840.113635.100.6.11.1 and the intermediate
// 1.2.840.113635.100.6.2.1; on the receipt path the signer must carry
// 1.2.840.113635.100.6.11.1. Without those, any Apple developer's own
// certificate — which chains through the same WWDR intermediate to the
// same pinned root — could sign a fully forged receipt (PLAN.md D13).
//
// Certificate validity is judged at the instant the payload says it was
// signed: signedDate, else receiptCreationDate, else the receipt's
// attribute-12 creation date, else the system clock. That is what lets a
// historical payload signed with a since-rotated certificate keep
// verifying. An injected clock cannot reach it — see [JWSVerifierOptions]
// Now.
//
// What signatures cannot tell you: a refund, a revocation or a renewal
// that happened after signing is invisible offline, and so is a replayed
// receipt. Track transaction ids server-side and use Apple's server API
// for current subscription state (INTENT.md).
//
// # Errors
//
// Every failed verification returns a [*VerificationError] carrying one
// of the eleven [Reason] constants and nothing else — no logging, no
// metrics, no callbacks (PLAN.md D11). Read it with errors.As:
//
//	var verr *applereceipt.VerificationError
//	if errors.As(err, &verr) && verr.Reason == applereceipt.ReasonWrongEnvironment {
//		retryAgainstSandbox()
//	}
//
// A configuration mistake — no trust anchors, an empty bundle id — is a
// plain error from the New… constructor instead, because misconfiguration
// is a programming bug and not a verdict about a receipt.
//
// # Concurrency
//
// Every verifier is immutable after construction and safe for concurrent
// use by multiple goroutines.
//
// # Example
//
//	verifier, err := applereceipt.NewJWSVerifier(applereceipt.JWSVerifierOptions{
//		TrustedRoots:         applereceipt.AppleJWSRoots(),
//		BundleID:             "com.example.app",
//		AcceptedEnvironments: []applereceipt.Environment{
//			applereceipt.EnvironmentProduction,
//			applereceipt.EnvironmentSandbox,
//		},
//	})
//	if err != nil {
//		return err
//	}
//	payload, err := verifier.VerifyTransaction(jws)
package applereceipt
