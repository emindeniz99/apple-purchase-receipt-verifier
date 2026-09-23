package applereceipt

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// VerifyReceiptResult is the outcome of one [VerifyReceiptEndpoint] call:
// the Apple status, the verified receipt or the reason there is none, and
// Apple's response body, rendered only when asked for.
//
// Exactly one of Receipt and Reason is set. The receipt is present
// whenever its bytes verified, including when the endpoint's own
// environment answers 21007 or 21008, so a caller can re-render for the
// other environment with ResponseFor or JSONFor without verifying twice.
// The status is always derived from the receipt's own receipt_type, so no
// render can answer 0 for a receipt from the wrong environment.
//
// Only the endpoint creates a meaningful result, and it never changes
// after that, so a result is safe for concurrent use. The zero value
// reports ReasonInternalError and status 21009, never a success.
//
// A result marshals with encoding/json as Apple's response body, the same
// bytes as JSON.
type VerifyReceiptResult struct {
	environment Environment
	pacific     *time.Location
	receipt     *AppReceipt
	// production is the routing verdict, fixed at verification so that a
	// caller modifying the shared *AppReceipt cannot change a status.
	production  bool
	err         *VerificationError
	requestDate time.Time
}

// Status is the Apple status for the endpoint's own environment: 0,
// 21002, 21003, 21007, 21008 or 21009.
func (r *VerifyReceiptResult) Status() int {
	return r.status(r.environment)
}

// Verified reports whether the receipt verified, true exactly when
// Receipt is non-nil. That includes 21007 and 21008 results: the receipt
// verified, only its environment differs from the endpoint's own, so this
// is NOT the same check as Status() == StatusOK. Status() == StatusOK
// answers "does this endpoint's environment accept the receipt";
// Verified answers "did the receipt verify at all", which is what to
// check before trusting Receipt's fields or re-rendering with
// ResponseFor.
func (r *VerifyReceiptResult) Verified() bool {
	return r.receipt != nil
}

// Receipt is the verified receipt, or nil when verification failed. It
// is present for 21007 and 21008 too: those say the receipt belongs to
// the other environment, not that it failed to verify.
//
// The pointer is shared with the result and with every later render;
// treat it as read-only.
func (r *VerifyReceiptResult) Receipt() *AppReceipt {
	return r.receipt
}

// Reason is why there is no receipt. It is empty exactly when Receipt is
// non-nil. Besides the verifier reasons it can be
// ReasonMalformedRequest, ReasonRequestTooLarge or ReasonInternalError,
// which only a result reports.
func (r *VerifyReceiptResult) Reason() Reason {
	if failure := r.failure(); failure != nil {
		return failure.Reason
	}
	return ""
}

// Err is the failure as a [*VerificationError], or nil when the receipt
// verified. For a verifier reason it is the error the verification
// returned. For ReasonInternalError, errors.Unwrap gives the unexpected
// error or panic behind it.
func (r *VerifyReceiptResult) Err() error {
	if failure := r.failure(); failure != nil {
		return failure
	}
	return nil
}

func (r *VerifyReceiptResult) failure() *VerificationError {
	switch {
	case r.err != nil:
		return r.err
	case r.receipt == nil:
		return newError(ReasonInternalError, "this VerifyReceiptResult was not created by a VerifyReceiptEndpoint")
	default:
		return nil
	}
}

// RequestDate is the instant rendered as request_date, fixed when the
// call was made.
func (r *VerifyReceiptResult) RequestDate() time.Time {
	return r.requestDate
}

// Response is the body the endpoint's own environment answers, built
// anew on each call. It carries a receipt and an environment only with
// status 0.
func (r *VerifyReceiptResult) Response() VerifyReceiptResponse {
	return r.response(r.environment)
}

// JSON is Response serialized as the JSON response body.
func (r *VerifyReceiptResult) JSON() []byte {
	return marshalResponse(r.Response())
}

// ResponseFor is the body an endpoint of environment would answer for
// the same receipt, at the same RequestDate. A production receipt
// answers 0 on Production and 21008 on Sandbox; any other receipt
// answers 21007 on Production and 0 on Sandbox; a failed result answers
// its own status on both. Any environment other than Production or
// Sandbox is an error, as it is for NewVerifyReceiptEndpoint.
func (r *VerifyReceiptResult) ResponseFor(environment Environment) (VerifyReceiptResponse, error) {
	if err := checkEndpointEnvironment(environment); err != nil {
		return VerifyReceiptResponse{}, err
	}
	return r.response(environment), nil
}

// JSONFor is ResponseFor serialized as the JSON response body.
func (r *VerifyReceiptResult) JSONFor(environment Environment) ([]byte, error) {
	response, err := r.ResponseFor(environment)
	if err != nil {
		return nil, err
	}
	return marshalResponse(response), nil
}

// MarshalJSON renders the result as JSON does, so a result handed to
// encoding/json becomes Apple's response body rather than "{}".
func (r *VerifyReceiptResult) MarshalJSON() ([]byte, error) {
	return r.JSON(), nil
}

func (r *VerifyReceiptResult) response(environment Environment) VerifyReceiptResponse {
	status := r.status(environment)
	if status != StatusOK {
		return VerifyReceiptResponse{Status: status}
	}
	return VerifyReceiptResponse{
		Status:      StatusOK,
		Environment: environment,
		Receipt:     r.receiptJSON(r.receipt, r.requestDate),
	}
}

func (r *VerifyReceiptResult) status(environment Environment) int {
	if r.receipt == nil {
		switch r.Reason() {
		case ReasonMalformedRequest, ReasonRequestTooLarge, ReasonInvalidReceiptFormat:
			return StatusMalformed
		case ReasonInternalError:
			return StatusInternal
		default:
			return StatusNotAuthenticated
		}
	}
	if environment == EnvironmentProduction && !r.production {
		return StatusSandboxReceiptOnProduction
	}
	if environment == EnvironmentSandbox && r.production {
		return StatusProductionReceiptOnSandbox
	}
	return StatusOK
}

func marshalResponse(response VerifyReceiptResponse) []byte {
	out, err := json.Marshal(response)
	if err != nil {
		return []byte(`{"status":` + strconv.Itoa(StatusInternal) + `}`)
	}
	return out
}

// checkEndpointEnvironment narrows the four-valued Environment to the two
// Apple runs a verifyReceipt host for.
func checkEndpointEnvironment(environment Environment) error {
	if environment != EnvironmentProduction && environment != EnvironmentSandbox {
		return fmt.Errorf(
			"applereceipt: Environment must be %q or %q, got %q",
			EnvironmentProduction, EnvironmentSandbox, environment)
	}
	return nil
}
