package applereceipt

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/emindeniz99/apple-purchase-receipt-verifier/go/internal/host"
)

// Verifier verifies what Apple signed, offline, against the pinned roots
// of a Config. It answers one question: did Apple sign this data, under a
// pinned Apple root? If so, it returns the data. Bundle id, environment,
// product id, device binding, refunds and idempotency are the caller's
// decisions; no method here takes a parameter for any of them.
//
// Every decision is made by aprv.wasm, the one verification module every
// port of this library runs, which is embedded in this package and run
// with wazero: pure Go, no cgo, no native code. A Verifier reads the
// clock, moves the input in and the answer out, and turns what the module
// says into Go values. It owns a small pool of module instances, each
// created and set up on first need and dropped with the Verifier; there is
// nothing to close.
//
// A Verifier is immutable after construction and safe for concurrent use
// by multiple goroutines. The verify methods never panic for any input. A
// failure of the machinery itself (the module trapped, gave an answer this
// package cannot read, or the configured clock panicked) is
// ReasonInternalError, with the category in the cause.
type Verifier struct {
	pool  *host.Pool
	clock func() int64
}

// NewVerifier builds a Verifier from config.
//
// A nil config, or one with no trust anchors or a nil one, is a plain error, never a
// *Failure: misconfiguration is a programming mistake, not a verdict about
// any input: a verifier with no roots would answer UNTRUSTED_CHAIN to
// everything, and nobody would notice until production, and a caller
// switching on Reason must never see one.
//
// The first Verifier of a process compiles the module, which takes about a
// second; later ones take a few milliseconds. NewVerifier also returns a
// plain error when the module refuses a trust anchor (one that is not a
// certificate) or is not the module this package binds.
func NewVerifier(config *Config) (*Verifier, error) {
	if err := checkConfig(config); err != nil {
		return nil, err
	}
	pool, err := host.NewPool(initConfig(config.roots, config.builtin))
	if err != nil {
		return nil, fmt.Errorf("applereceipt: %w", err)
	}
	return &Verifier{pool: pool, clock: config.clock}, nil
}

// checkConfig is the caller-misuse half of NewVerifier: the mistakes that
// need no module to see.
func checkConfig(config *Config) error {
	if config == nil {
		return errors.New("applereceipt: config must not be nil")
	}
	if !config.builtin && len(config.roots) == 0 {
		return errors.New("applereceipt: config has no trust anchors")
	}
	if slices.Contains(config.roots, nil) {
		return errors.New("applereceipt: config has a nil trust anchor")
	}
	return nil
}

// VerifyReceipt verifies a legacy PKCS#7 app receipt, given as the base64
// string a client sends, and decodes its payload.
func (v *Verifier) VerifyReceipt(base64 string) (payload *ReceiptPayload, err error) {
	defer contain(&err)
	now, err := v.now()
	if err != nil {
		return nil, err
	}
	answer, err := v.pool.VerifyReceipt(now, base64)
	if err != nil {
		return nil, hostFailure(err)
	}
	result, environment, err := readResult(answer)
	if err != nil {
		return nil, err
	}
	payload, err = receiptFromJSON(result, environment)
	if err != nil {
		return nil, unreadableAnswer(err)
	}
	return payload, nil
}

// VerifySignedData verifies an Apple-signed compact JWS (StoreKit 2
// jwsRepresentation, signedTransactionInfo / signedRenewalInfo, an
// AppTransaction, or an outer or nested App Store Server Notifications V2
// JWS) and returns its payload, exactly as signed.
func (v *Verifier) VerifySignedData(jws string) (payload *JSONPayload, err error) {
	defer contain(&err)
	now, err := v.now()
	if err != nil {
		return nil, err
	}
	answer, err := v.pool.VerifySignedData(now, jws)
	if err != nil {
		return nil, hostFailure(err)
	}
	result, environment, err := readResult(answer)
	if err != nil {
		return nil, err
	}
	var signed string
	if err := json.Unmarshal(result, &signed); err != nil {
		return nil, unreadableAnswer(errors.New("the payload is not a JSON string"))
	}
	return &JSONPayload{json: signed, environment: environment}, nil
}

// VerifyReceiptEndpoint is the response body Apple's deprecated
// verifyReceipt endpoint at environment would return for requestJSON,
// verified offline against the pinned roots instead of by calling Apple.
//
// It never returns an error and never panics: like the real endpoint,
// every failure is the status field inside the returned body. The module
// or the clock failing is StatusInternalDataAccessError, and so is an
// environment that is neither of the two constants.
func (v *Verifier) VerifyReceiptEndpoint(environment Environment, requestJSON string) (out string) {
	failed := statusOnlyResponse(StatusInternalDataAccessError)
	defer func() {
		if recover() != nil {
			out = failed
		}
	}()
	var env uint32
	switch environment {
	case EnvironmentProduction:
		env = 0
	case EnvironmentSandbox:
		env = 1
	default:
		return failed
	}
	now, err := v.now()
	if err != nil {
		return failed
	}
	answer, err := v.pool.VerifyReceiptEndpoint(env, now, requestJSON)
	if err != nil || !utf8.ValidString(answer) || !json.Valid([]byte(answer)) {
		return failed
	}
	return answer
}

// now reads the configured clock, once per call and before the input is
// looked at, as epoch milliseconds for the module. A clock that panics or
// answers a time before 1970 is ReasonInternalError regardless of the
// input: the caller's clock broke, not the input.
func (v *Verifier) now() (millis uint64, err error) {
	if v == nil || v.pool == nil {
		return 0, newError(ReasonInternalError, "the Verifier was not made by NewVerifier")
	}
	defer func() {
		if recover() != nil {
			err = newError(ReasonInternalError, "the configured clock panicked")
		}
	}()
	instant := v.clock()
	if instant < 0 {
		return 0, newError(ReasonInternalError, "the configured clock answered a time before 1970")
	}
	return uint64(instant), nil
}

// contain turns a panic in this package's own code into a *Failure. Nothing
// here is expected to panic: this is the promise that no input can make a
// verify method do so. Deferred directly in each verify method, so the
// named error return still holds nil until this runs.
func contain(err *error) {
	if recover() != nil {
		*err = newError(ReasonInternalError, "unexpected internal failure")
	}
}

// hostFailure is a call that ended in the machinery, not in a verdict. The
// message names the category; the cause has the detail, so a caller who
// looks can tell a trap from an answer nobody could read.
func hostFailure(cause error) *Failure {
	var trap *host.TrapError
	var result *host.ResultError
	switch {
	case errors.As(cause, &trap):
		return wrapError(ReasonInternalError, cause, "the verification module trapped")
	case errors.As(cause, &result):
		return wrapError(ReasonInternalError, cause, "the verification module's answer was unusable")
	default:
		return wrapError(ReasonInternalError, cause, "the verification module could not be run")
	}
}

func unreadableAnswer(cause error) *Failure {
	return wrapError(ReasonInternalError, cause, "the verification module's answer was unusable")
}

// readResult reads the envelope of an answer: a failure becomes a
// *Failure, a success yields the payload's JSON and the environment beside
// it (nil for null). An answer that is not in the wire's shape, or names a
// reason outside the eight or an environment outside the two, is unusable
// and therefore INTERNAL_ERROR: this never guesses at what a module meant.
func readResult(answer string) (payload json.RawMessage, environment *Environment, err error) {
	var wire struct {
		Verified *bool            `json:"verified"`
		Reason   *string          `json:"reason"`
		Message  *string          `json:"message"`
		Payload  *json.RawMessage `json:"payload"`
		// Not a pointer: a RawMessage holds null as the text null, so a
		// missing member (empty) and a null one stay apart.
		Environment json.RawMessage `json:"environment"`
	}
	if !utf8.ValidString(answer) {
		return nil, nil, unreadableAnswer(errors.New("the answer is not UTF-8"))
	}
	decoder := json.NewDecoder(strings.NewReader(answer))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil || wire.Verified == nil {
		return nil, nil, unreadableAnswer(errors.New("the answer is not a verification result"))
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, nil, unreadableAnswer(errors.New("the answer has content after the result"))
	}
	if *wire.Verified {
		if wire.Payload == nil || wire.Reason != nil || wire.Message != nil {
			return nil, nil, unreadableAnswer(errors.New("a verified result must carry a payload, an environment and nothing else"))
		}
		environment, err := environmentFromJSON(wire.Environment)
		if err != nil {
			return nil, nil, unreadableAnswer(err)
		}
		return *wire.Payload, environment, nil
	}
	if wire.Reason == nil || wire.Payload != nil || wire.Environment != nil {
		return nil, nil, unreadableAnswer(errors.New("a failed result must carry a reason and no payload"))
	}
	reason := Reason(*wire.Reason)
	if !slices.Contains(AllReasons(), reason) {
		return nil, nil, unreadableAnswer(fmt.Errorf("the reason %q is not one of the eight", *wire.Reason))
	}
	message := ""
	if wire.Message != nil {
		message = *wire.Message
	}
	return nil, nil, &Failure{Reason: reason, Message: message}
}

// environmentFromJSON reads the environment member of a verified answer:
// "Production", "Sandbox" or null (nil). A missing member or any other
// value is not the wire's shape.
func environmentFromJSON(raw json.RawMessage) (*Environment, error) {
	if string(raw) == "null" {
		return nil, nil
	}
	var text string
	if raw != nil && json.Unmarshal(raw, &text) == nil {
		switch environment := Environment(text); environment {
		case EnvironmentProduction, EnvironmentSandbox:
			return &environment, nil
		}
	}
	return nil, errors.New("a verified result must carry an environment of Production, Sandbox or null")
}
