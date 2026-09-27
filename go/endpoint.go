package applereceipt

import (
	"crypto/x509"
	"encoding/json"
	"strconv"
)

// VerifyReceiptEndpoint answers Apple's verifyReceipt request bodies
// locally: the same response shape and the same status codes, verified
// offline against pinned Apple roots instead of by calling Apple.
//
// Field-by-field fidelity and the unavoidable gaps (fields that exist only
// in Apple's server-side subscription database, such as
// latest_receipt_info and pending_renewal_info) are documented in
// COMPARISON.md. Like Apple's endpoint, it does NOT check the bundle id:
// the caller compares receipt.bundle_id, exactly as with the real
// endpoint.

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

// MaxRequestBytes is the ceiling on a raw verifyReceipt request body, in
// UTF-8 bytes: 3 MiB, Apple's own limit, fixed and the same in every port
// of this library. Measured on 2026-09-23 against both of Apple's
// verifyReceipt endpoints, a body of 3,145,728 bytes is answered and one
// of 3,145,729 bytes gets HTTP 413. A larger body is StatusMalformedReceiptData,
// decided before the depth scan and before parsing.
const MaxRequestBytes = 3_145_728

// verifyReceiptEndpoint is Verifier.VerifyReceiptEndpoint's
// implementation.
func verifyReceiptEndpoint(environment Environment, requestJSON string, anchors []*x509.Certificate, ctx *verifyCtx) string {
	receiptData, rerr := requestReceiptData(requestJSON)
	if rerr != nil {
		return statusOnlyResponse(statusForReason(rerr.Reason))
	}
	payload, verr := verifyReceipt(receiptData, anchors, ctx)
	if verr != nil {
		reason, _ := ReasonOf(verr)
		return statusOnlyResponse(statusForReason(reason))
	}
	production := false
	if payload.ReceiptType != nil {
		if env, ok := FromReceiptType(*payload.ReceiptType); ok {
			production = env == EnvironmentProduction
		}
	}
	switch {
	case environment == EnvironmentProduction && !production:
		return statusOnlyResponse(StatusSandboxReceiptOnProduction)
	case environment == EnvironmentSandbox && production:
		return statusOnlyResponse(StatusProductionReceiptOnSandbox)
	}
	requestDateMs, cerr := ctx.now()
	if cerr != nil {
		reason, _ := ReasonOf(cerr)
		return statusOnlyResponse(statusForReason(reason))
	}
	return renderEndpointResponse(environment, payload, requestDateMs)
}

// requestReceiptData reads the receipt-data string out of a verifyReceipt
// request body. A body over MaxRequestBytes is ReasonTooLarge; a body
// that is not a JSON object (unparseable, null, an array, a scalar), that
// nests deeper than MaxJSONNestingDepth, or whose receipt-data is missing
// or not a string, is ReasonMalformed. Both caps are checked before the
// body is parsed, the size first. The whole object is read, so a
// duplicate receipt-data's last value wins, as it would in a map;
// password and exclude-old-transactions are read for wire compatibility
// and never used.
func requestReceiptData(requestJSON string) (string, *Failure) {
	if len(requestJSON) > MaxRequestBytes {
		return "", newError(ReasonTooLarge, "the request body exceeds the %d byte limit", MaxRequestBytes)
	}
	body := []byte(requestJSON)
	if jsonBoundsExceeded(body, MaxJSONNestingDepth, MaxJSONMemberNameLength, MaxJSONNumberDigits) {
		return "", newError(ReasonMalformed, "the request body exceeds a JSON bound (nesting, member name length, or number length)")
	}
	object, err := decodeJSONObject(body)
	if err != nil {
		return "", newError(ReasonMalformed, "the request body is not a JSON object")
	}
	receiptData, ok := object["receipt-data"].(string)
	if !ok {
		return "", newError(ReasonMalformed, "receipt-data is missing or not a string")
	}
	return receiptData, nil
}

// statusForReason is the status the endpoint answers for a verification
// failure, the same table in every port.
func statusForReason(reason Reason) int {
	switch reason {
	case ReasonMalformed, ReasonTooLarge:
		return StatusMalformedReceiptData
	case ReasonInvalidSignature, ReasonUntrustedChain, ReasonInvalidCertificate, ReasonInvalidCertificatePurpose:
		return StatusNotAuthenticated
	default: // ReasonUnreadablePayload, ReasonInternalError
		return StatusInternalDataAccessError
	}
}

func statusOnlyResponse(status int) string {
	return `{"status":` + strconv.Itoa(status) + `}`
}

// renderEndpointResponse is the status-0 response body: status,
// environment and the rendered receipt. Keys follow Apple's endpoint; their
// order is deterministic but not part of the contract.
func renderEndpointResponse(environment Environment, receipt *ReceiptPayload, requestDateMs int64) string {
	// Marshal cannot fail on strings, integers, slices and string-keyed
	// maps.
	out, _ := json.Marshal(struct {
		Status      int            `json:"status"`
		Environment string         `json:"environment"`
		Receipt     map[string]any `json:"receipt"`
	}{StatusOK, environment.String(), endpointReceipt(receipt, requestDateMs)})
	return string(out)
}

func endpointReceipt(receipt *ReceiptPayload, requestDateMs int64) map[string]any {
	m := map[string]any{}
	presentStr(m, "receipt_type", receipt.ReceiptType)
	// Apple echoes attribute 1 under both names (its response reference
	// defines adam_id as "See app_item_id"), and as JSON numbers, not as
	// the strings the in-app integers are rendered with.
	presentNum(m, "adam_id", receipt.AppItemID)
	presentNum(m, "app_item_id", receipt.AppItemID)
	presentStr(m, "bundle_id", receipt.BundleID)
	presentStr(m, "application_version", receipt.ApplicationVersion)
	presentNum(m, "download_id", receipt.DownloadID)
	presentNum(m, "version_external_identifier", receipt.VersionExternalIdentifier)
	presentStr(m, "original_application_version", receipt.OriginalApplicationVersion)
	appleDates(m, "receipt_creation_date", receipt.ReceiptCreationDateMs)
	requestDate := requestDateMs
	appleDates(m, "request_date", &requestDate)
	appleDates(m, "original_purchase_date", receipt.OriginalPurchaseDateMs)
	appleDates(m, "expiration_date", receipt.ExpirationDateMs)
	inApp := make([]map[string]any, len(receipt.InApp))
	for i := range receipt.InApp {
		inApp[i] = endpointPurchase(&receipt.InApp[i])
	}
	m["in_app"] = inApp
	return m
}

func endpointPurchase(purchase *InAppPurchase) map[string]any {
	m := map[string]any{}
	if purchase.Quantity != nil {
		m["quantity"] = strconv.FormatInt(*purchase.Quantity, 10)
	} else {
		m["quantity"] = nil
	}
	presentStr(m, "product_id", purchase.ProductID)
	presentStr(m, "transaction_id", purchase.TransactionID)
	presentStr(m, "original_transaction_id", purchase.OriginalTransactionID)
	appleDates(m, "purchase_date", purchase.PurchaseDateMs)
	appleDates(m, "original_purchase_date", purchase.OriginalPurchaseDateMs)
	appleDates(m, "expires_date", purchase.ExpiresDateMs)
	appleDates(m, "cancellation_date", purchase.CancellationDateMs)
	// Apple omits the key when attribute 1711 is 0, as it does for
	// consumables.
	if purchase.WebOrderLineItemID != nil && *purchase.WebOrderLineItemID != 0 {
		m["web_order_line_item_id"] = strconv.FormatInt(*purchase.WebOrderLineItemID, 10)
	}
	presentBoolString(m, "is_trial_period", purchase.IsTrialPeriod)
	presentBoolString(m, "is_in_intro_offer_period", purchase.IsInIntroOfferPeriod)
	return m
}

func presentStr(m map[string]any, key string, value *string) {
	if value != nil && *value != "" {
		m[key] = *value
	}
}

func presentNum(m map[string]any, key string, value *int64) {
	if value != nil {
		m[key] = *value
	}
}

func presentBoolString(m map[string]any, key string, value *bool) {
	if value != nil {
		m[key] = strconv.FormatBool(*value)
	}
}

// appleDates writes Apple's three renderings of one instant: the GMT
// form, the epoch-millisecond form as a decimal string, and the US
// Pacific form. Apple labels the first "Etc/GMT": that string is part of
// the wire contract, not a description.
func appleDates(m map[string]any, prefix string, ms *int64) {
	if ms == nil {
		return
	}
	m[prefix] = formatAppleDate(*ms, 0, "Etc/GMT")
	m[prefix+"_ms"] = strconv.FormatInt(*ms, 10)
	m[prefix+"_pst"] = formatAppleDate(*ms, pacificOffsetSeconds(*ms), "America/Los_Angeles")
}
