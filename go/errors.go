package applereceipt

import (
	"errors"
	"fmt"
)

// Reason is the machine-readable cause of a verification failure.
//
// The eight constants below are the complete vocabulary a verifier
// returns. It is closed by the cross-port contract
// (fixtures/cases.schema.json); a ninth reason is a change to every
// implementation in one go, not a Go-local addition.
type Reason string

// The error vocabulary. The string values are normative: they are the
// tokens fixtures/cases.json pins and every port reports, so
// string(reason) is the canonical wire form.
const (
	// ReasonMalformed: the base64, ASN.1, CMS or JWS structure is broken,
	// or a structural bound (ASN.1 depth, embedded certificates,
	// SignerInfos) is exceeded.
	ReasonMalformed Reason = "MALFORMED"
	// ReasonTooLarge: the input is over one of the fixed size caps.
	ReasonTooLarge Reason = "TOO_LARGE"
	// ReasonInvalidSignature: the signature does not match the content.
	ReasonInvalidSignature Reason = "INVALID_SIGNATURE"
	// ReasonUntrustedChain: the chain does not reach a pinned root.
	ReasonUntrustedChain Reason = "UNTRUSTED_CHAIN"
	// ReasonInvalidCertificate: a certificate does not decode, or is
	// outside its validity window at the chain instant.
	ReasonInvalidCertificate Reason = "INVALID_CERTIFICATE"
	// ReasonInvalidCertificatePurpose: a valid Apple certificate of the
	// wrong kind, an Apple marker OID is missing.
	ReasonInvalidCertificatePurpose Reason = "INVALID_CERTIFICATE_PURPOSE"
	// ReasonUnreadablePayload: Apple signed it, but the content does not
	// parse.
	ReasonUnreadablePayload Reason = "UNREADABLE_PAYLOAD"
	// ReasonInternalError is not the client's fault: the library failed
	// before it could decide, found only after the chain and the
	// signature passed (for a receipt or a signed payload, Unwrap gives
	// the parser's error), or the configured clock panicked. Alert; do
	// not retry.
	ReasonInternalError Reason = "INTERNAL_ERROR"
)

// AllReasons is the whole vocabulary, in the order the shared schema
// lists it.
func AllReasons() []Reason {
	return []Reason{
		ReasonMalformed,
		ReasonTooLarge,
		ReasonInvalidSignature,
		ReasonUntrustedChain,
		ReasonInvalidCertificate,
		ReasonInvalidCertificatePurpose,
		ReasonUnreadablePayload,
		ReasonInternalError,
	}
}

// Error lets a bare Reason be used as an errors.Is target:
//
//	if errors.Is(err, applereceipt.ReasonUntrustedChain) { … }
//
// The canonical read is errors.As on *Failure; this is sugar.
func (r Reason) Error() string { return string(r) }

// String returns the canonical SCREAMING_SNAKE token.
func (r Reason) String() string { return string(r) }

// Failure is the only error type a verification method returns. Match on
// Reason; Message is safe to log (it never embeds raw input, and control
// characters and bidi controls quoted from the input are neutralised) but
// is not meant to be parsed and may change between releases.
//
// Cause, reached through errors.Unwrap, is nil for every verdict of the
// verification module: its own cause chain stays inside the module, and
// Message carries the reason. It is set when ReasonInternalError comes from
// this package's machinery rather than from the module, and names what
// happened (a trap, an answer that could not be read, the clock); it never
// carries raw library text that might quote certificate names from the
// input.
//
// Read it with errors.As:
//
//	var failure *applereceipt.Failure
//	if errors.As(err, &failure) {
//		switch failure.Reason {
//		case applereceipt.ReasonUntrustedChain:
//			alertSecurity()
//		}
//	}
//
// errors.Is(err, applereceipt.ReasonUntrustedChain) also works, as sugar;
// errors.As is canonical because it also carries Message and Cause.
type Failure struct {
	Reason  Reason
	Message string
	Cause   error // wrapped cause; may be nil
}

func (e *Failure) Error() string {
	if e == nil {
		return "<nil *Failure>"
	}
	return string(e.Reason) + ": " + e.Message
}

// Unwrap exposes the wrapped cause to errors.Is / errors.As.
func (e *Failure) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Is reports whether target is this error's Reason, so
// errors.Is(err, ReasonUntrustedChain) works.
func (e *Failure) Is(target error) bool {
	if e == nil {
		return false
	}
	r, ok := target.(Reason)
	return ok && r == e.Reason
}

// ReasonOf extracts the Reason from err, if err is (or wraps) a *Failure.
// It is the switch-on-reason convenience over errors.As.
func ReasonOf(err error) (Reason, bool) {
	var failure *Failure
	if errors.As(err, &failure) && failure != nil {
		return failure.Reason, true
	}
	return "", false
}

func newError(reason Reason, format string, args ...any) *Failure {
	return &Failure{Reason: reason, Message: fmt.Sprintf(format, args...)}
}

func wrapError(reason Reason, cause error, format string, args ...any) *Failure {
	return &Failure{Reason: reason, Message: fmt.Sprintf(format, args...), Cause: cause}
}
