package applereceipt

import (
	"errors"

	"github.com/emindeniz99/apple-purchase-receipt-verifier/go/internal/apperr"
)

// Reason is the machine-readable cause of a verification failure.
//
// The eleven constants below are the complete vocabulary. It is closed by
// the cross-port contract (fixtures/cases.schema.json); a twelfth reason
// is a change to every implementation in one go, not a Go-local addition.
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
