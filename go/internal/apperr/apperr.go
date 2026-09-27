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
// eight constants below are the complete vocabulary (docs/design/0.7-api.md,
// Result); it is closed by the cross-port contract
// (fixtures/cases-0.7.schema.json) and changing it is a cross-port change.
type Reason string

// The eight reasons. The string values are normative: they are the tokens
// fixtures/cases-0.7.json pins and every port reports.
const (
	ReasonMalformed                 Reason = "MALFORMED"
	ReasonTooLarge                  Reason = "TOO_LARGE"
	ReasonInvalidSignature          Reason = "INVALID_SIGNATURE"
	ReasonUntrustedChain            Reason = "UNTRUSTED_CHAIN"
	ReasonInvalidCertificate        Reason = "INVALID_CERTIFICATE"
	ReasonInvalidCertificatePurpose Reason = "INVALID_CERTIFICATE_PURPOSE"
	ReasonUnreadablePayload         Reason = "UNREADABLE_PAYLOAD"
	ReasonInternalError             Reason = "INTERNAL_ERROR"
)

// AllReasons is every reason, in the order fixtures/cases-0.7.schema.json
// lists them. Exposed so a test can assert the vocabulary is complete.
var AllReasons = []Reason{
	ReasonMalformed,
	ReasonTooLarge,
	ReasonInvalidSignature,
	ReasonUntrustedChain,
	ReasonInvalidCertificate,
	ReasonInvalidCertificatePurpose,
	ReasonUnreadablePayload,
	ReasonInternalError,
}

// Error lets a bare Reason be used as an errors.Is target:
//
//	if errors.Is(err, applereceipt.ReasonUntrustedChain) { … }
//
// The canonical read is errors.As on *Failure; this is sugar.
func (r Reason) Error() string { return string(r) }

// String returns the canonical SCREAMING_SNAKE token.
func (r Reason) String() string { return string(r) }

// Error is the one error type every exported verification entry point
// returns. Message is a short, log-safe explanation: it never contains
// receipt bytes, claim values or key material, and control characters and
// bidi controls quoted from the input are neutralised.
type Error struct {
	Reason  Reason
	Message string
	Cause   error // wrapped cause; may be nil
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil *Failure>"
	}
	return string(e.Reason) + ": " + e.Message
}

// Unwrap exposes the wrapped cause to errors.Is / errors.As.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Is reports whether target is this error's Reason, so
// errors.Is(err, ReasonUntrustedChain) works.
func (e *Error) Is(target error) bool {
	if e == nil {
		return false
	}
	r, ok := target.(Reason)
	return ok && r == e.Reason
}

// New builds an Error with no wrapped cause.
func New(reason Reason, format string, args ...any) *Error {
	return &Error{Reason: reason, Message: fmt.Sprintf(format, args...)}
}

// Wrap builds an Error carrying a cause.
func Wrap(reason Reason, cause error, format string, args ...any) *Error {
	return &Error{Reason: reason, Message: fmt.Sprintf(format, args...), Cause: cause}
}
