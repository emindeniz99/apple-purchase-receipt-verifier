// Package apperr holds the library's error vocabulary.
//
// It sits in internal/ so that the security-critical packages
// (internal/chain, internal/der) can raise the canonical reasons without
// importing the root package, which would be a cycle. The root package
// re-exports every identifier here under its documented name, and the
// types are aliases, so the concrete type a caller sees is one type.
package apperr

import "fmt"

// Reason is the machine-readable cause of a verification failure. The
// eleven constants below are the complete vocabulary; it is closed by
// fixtures/cases.schema.json and changing it is a cross-port change.
type Reason string

// The eleven reasons. The string values are normative: they are the tokens
// fixtures/cases.json pins and every port reports.
const (
	ReasonInvalidJWSFormat          Reason = "INVALID_JWS_FORMAT"
	ReasonInvalidCertificate        Reason = "INVALID_CERTIFICATE"
	ReasonInvalidCertificatePurpose Reason = "INVALID_CERTIFICATE_PURPOSE"
	ReasonInvalidChain              Reason = "INVALID_CHAIN"
	ReasonInvalidSignature          Reason = "INVALID_SIGNATURE"
	ReasonWrongBundleID             Reason = "WRONG_BUNDLE_ID"
	ReasonWrongEnvironment          Reason = "WRONG_ENVIRONMENT"
	ReasonWrongAppAppleID           Reason = "WRONG_APP_APPLE_ID"
	ReasonInvalidReceiptFormat      Reason = "INVALID_RECEIPT_FORMAT"
	ReasonDeviceHashMismatch        Reason = "DEVICE_HASH_MISMATCH"
	ReasonStalePayload              Reason = "STALE_PAYLOAD"
)

// AllReasons is every reason, in the order fixtures/cases.schema.json
// lists them. Exposed so a test can assert the vocabulary is complete.
var AllReasons = []Reason{
	ReasonInvalidJWSFormat,
	ReasonInvalidCertificate,
	ReasonInvalidCertificatePurpose,
	ReasonInvalidChain,
	ReasonInvalidSignature,
	ReasonWrongBundleID,
	ReasonWrongEnvironment,
	ReasonWrongAppAppleID,
	ReasonInvalidReceiptFormat,
	ReasonDeviceHashMismatch,
	ReasonStalePayload,
}

// Error lets a bare Reason be used as an errors.Is target:
//
//	if errors.Is(err, applereceipt.ReasonInvalidChain) { … }
//
// The canonical read is errors.As on *VerificationError; this is sugar.
func (r Reason) Error() string { return string(r) }

// String returns the canonical SCREAMING_SNAKE token.
func (r Reason) String() string { return string(r) }

// Error is the one error type every exported verification entry point
// returns. Detail is a short, log-safe explanation: it never contains
// receipt bytes, claim values or key material.
type Error struct {
	Reason Reason
	Detail string
	Err    error // wrapped cause; may be nil
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil *VerificationError>"
	}
	return string(e.Reason) + ": " + e.Detail
}

// Unwrap exposes the wrapped cause to errors.Is / errors.As.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Is reports whether target is this error's Reason, so
// errors.Is(err, ReasonInvalidChain) works.
func (e *Error) Is(target error) bool {
	if e == nil {
		return false
	}
	r, ok := target.(Reason)
	return ok && r == e.Reason
}

// New builds an Error with no wrapped cause.
func New(reason Reason, format string, args ...any) *Error {
	return &Error{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// Wrap builds an Error carrying a cause.
func Wrap(reason Reason, cause error, format string, args ...any) *Error {
	return &Error{Reason: reason, Detail: fmt.Sprintf(format, args...), Err: cause}
}
