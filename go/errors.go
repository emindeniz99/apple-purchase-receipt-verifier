package applereceipt

import (
	"errors"

	"github.com/emindeniz99/apple-purchase-receipt-verifier/go/internal/apperr"
)

// Reason is the machine-readable cause of a verification failure.
//
// The twelve constants below are the complete vocabulary a verifier
// returns. It is closed by the cross-port contract
// (fixtures/cases.schema.json); a thirteenth reason is a change to every
// implementation in one go, not a Go-local addition. A
// [VerifyReceiptResult] can also report ReasonMalformedRequest and
// ReasonRequestTooLarge, which every port's endpoint result shares.
type Reason = apperr.Reason

// The error vocabulary. The string values are normative — they are the
// tokens fixtures/cases.json pins and every port reports — so
// string(reason) is the canonical wire form.
const (
	ReasonInvalidJWSFormat          = apperr.ReasonInvalidJWSFormat
	ReasonInvalidCertificate        = apperr.ReasonInvalidCertificate
	ReasonInvalidCertificatePurpose = apperr.ReasonInvalidCertificatePurpose
	ReasonInvalidChain              = apperr.ReasonInvalidChain
	ReasonInvalidSignature          = apperr.ReasonInvalidSignature
	ReasonWrongBundleID             = apperr.ReasonWrongBundleID
	ReasonWrongEnvironment          = apperr.ReasonWrongEnvironment
	ReasonWrongAppAppleID           = apperr.ReasonWrongAppAppleID
	ReasonInvalidReceiptFormat      = apperr.ReasonInvalidReceiptFormat
	ReasonDeviceHashMismatch        = apperr.ReasonDeviceHashMismatch
	ReasonStalePayload              = apperr.ReasonStalePayload
	// ReasonInternalError is not the client's fault. A verifier returns it
	// when a trusted signer signed receipt content or a modelled JWS claim
	// this library cannot read, found only after the chain and the
	// signature passed (for a receipt, Unwrap gives the parser's error), or
	// when the runtime cannot compute the device hash; a
	// VerifyReceiptEndpoint also reports it for an unexpected error or
	// panic inside it. Status 21009. Alert and
	// retry or escalate; do not deny the user on it.
	ReasonInternalError = apperr.ReasonInternalError
)

// Two more reasons exist only on a [VerifyReceiptResult]. No verifier
// returns either, and neither is in AllReasons, which is the shared
// schema's vocabulary.
const (
	// ReasonMalformedRequest: the verifyReceipt request envelope is
	// unusable. The body is not a JSON object or nests deeper than
	// MaxJSONNestingDepth, or receipt-data is missing, empty or not a
	// string. Status 21002.
	ReasonMalformedRequest = apperr.ReasonMalformedRequest
	// ReasonRequestTooLarge: the raw request body is over
	// MaxRequestBytes (3,145,728 bytes), the size at which Apple's
	// endpoint answers HTTP 413. Status 21002 in the response body; an
	// HTTP layer can map it to 413 as Apple does.
	ReasonRequestTooLarge = apperr.ReasonRequestTooLarge
)

// AllReasons is the whole vocabulary, in the order the shared schema
// lists it.
func AllReasons() []Reason { return append([]Reason(nil), apperr.AllReasons...) }

// VerificationError is the only error type a verification entry point
// returns. Read it with errors.As:
//
//	var verr *applereceipt.VerificationError
//	if errors.As(err, &verr) {
//		switch verr.Reason {
//		case applereceipt.ReasonWrongEnvironment:
//			retryAgainstSandbox()
//		case applereceipt.ReasonInvalidChain:
//			alertSecurity()
//		}
//	}
//
// errors.Is(err, applereceipt.ReasonStalePayload) also works, as sugar;
// errors.As is canonical because it also carries Detail and the cause.
//
// Detail is safe to log: it never contains receipt bytes, claim values or
// key material (PLAN.md D11 — the reason code is the whole observability
// surface).
type VerificationError = apperr.Error

// ReasonOf extracts the Reason from err, if err is (or wraps) a
// *VerificationError. It is the switch-on-reason convenience over
// errors.As.
func ReasonOf(err error) (Reason, bool) {
	var verr *VerificationError
	if errors.As(err, &verr) && verr != nil {
		return verr.Reason, true
	}
	return "", false
}

func newError(reason Reason, format string, args ...any) *VerificationError {
	return apperr.New(reason, format, args...)
}

func wrapError(reason Reason, cause error, format string, args ...any) *VerificationError {
	return apperr.Wrap(reason, cause, format, args...)
}
