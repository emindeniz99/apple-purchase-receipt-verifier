package applereceipt

import "strconv"

// AppleStatus names every status code Apple documents for verifyReceipt.
// This library's VerifyReceiptEndpoint can answer StatusOK,
// StatusMalformedReceiptData, StatusNotAuthenticated,
// StatusSandboxReceiptOnProduction, StatusProductionReceiptOnSandbox and
// StatusInternalDataAccessError, and never the others; 21005 and the
// 21100-21199 range mean Apple's own servers failed and invite a retry,
// which an offline endpoint cannot answer either way, so it never returns
// them. Both InternalDataAccessError verdicts are deterministic for the
// same input: alert, do not retry.
const (
	// StatusOK: the receipt is valid.
	StatusOK = 0
	// StatusRequestNotPost: the request was not an HTTP POST. Out of
	// scope for a body-level API; never returned.
	StatusRequestNotPost = 21000
	// StatusMalformedReceiptData: the receipt-data property was malformed
	// or missing.
	StatusMalformedReceiptData = 21002
	// StatusNotAuthenticated: the receipt could not be authenticated.
	StatusNotAuthenticated = 21003
	// StatusSandboxReceiptOnProduction: a sandbox receipt was sent to the
	// production environment.
	StatusSandboxReceiptOnProduction = 21007
	// StatusProductionReceiptOnSandbox: a production receipt was sent to
	// the sandbox environment.
	StatusProductionReceiptOnSandbox = 21008
	// StatusInternalDataAccessError: an internal data access error.
	StatusInternalDataAccessError = 21009
)

// statusOnlyResponse is the body of an answer that is only a status: what
// this wrapper says when the module could not.
func statusOnlyResponse(status int) string {
	return `{"status":` + strconv.Itoa(status) + `}`
}
