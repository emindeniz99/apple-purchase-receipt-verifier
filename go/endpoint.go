package applereceipt

import (
	"crypto/x509"
	"strconv"
	"strings"
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
// environment and the rendered receipt. Key order follows Apple's
// endpoint; it is deterministic but not part of the contract.
func renderEndpointResponse(environment Environment, receipt *ReceiptPayload, requestDateMs int64) string {
	var b strings.Builder
	b.Grow(1024 + 1024*len(receipt.InApp))
	w := newJSONWriter(&b)
	statusValue := int64(StatusOK)
	w.num("status", &statusValue)
	env := environment.String()
	w.str("environment", &env)
	w.key("receipt")
	writeEndpointReceipt(&b, receipt, requestDateMs)
	w.close()
	return b.String()
}

func writeEndpointReceipt(out *strings.Builder, receipt *ReceiptPayload, requestDateMs int64) {
	w := newJSONWriter(out)
	presentStr(w, "receipt_type", receipt.ReceiptType)
	// Apple echoes attribute 1 under both names (its response reference
	// defines adam_id as "See app_item_id"), and as JSON numbers, not as
	// the strings the in-app integers are rendered with.
	presentNum(w, "adam_id", receipt.AppItemID)
	presentNum(w, "app_item_id", receipt.AppItemID)
	presentStr(w, "bundle_id", receipt.BundleID)
	presentStr(w, "application_version", receipt.ApplicationVersion)
	presentNum(w, "download_id", receipt.DownloadID)
	presentNum(w, "version_external_identifier", receipt.VersionExternalIdentifier)
	presentStr(w, "original_application_version", receipt.OriginalApplicationVersion)
	appleDates(w, "receipt_creation_date", receipt.ReceiptCreationDateMs)
	requestDate := requestDateMs
	appleDates(w, "request_date", &requestDate)
	appleDates(w, "original_purchase_date", receipt.OriginalPurchaseDateMs)
	appleDates(w, "expiration_date", receipt.ExpirationDateMs)
	w.arrayStart("in_app")
	for i := range receipt.InApp {
		if i > 0 {
			out.WriteByte(',')
		}
		writeEndpointPurchase(out, &receipt.InApp[i])
	}
	w.arrayEnd()
	w.close()
}

func writeEndpointPurchase(out *strings.Builder, purchase *InAppPurchase) {
	w := newJSONWriter(out)
	if purchase.Quantity != nil {
		quantity := strconv.FormatInt(*purchase.Quantity, 10)
		w.str("quantity", &quantity)
	} else {
		w.str("quantity", nil)
	}
	presentStr(w, "product_id", purchase.ProductID)
	presentStr(w, "transaction_id", purchase.TransactionID)
	presentStr(w, "original_transaction_id", purchase.OriginalTransactionID)
	appleDates(w, "purchase_date", purchase.PurchaseDateMs)
	appleDates(w, "original_purchase_date", purchase.OriginalPurchaseDateMs)
	appleDates(w, "expires_date", purchase.ExpiresDateMs)
	appleDates(w, "cancellation_date", purchase.CancellationDateMs)
	// Apple omits the key when attribute 1711 is 0, as it does for
	// consumables.
	if purchase.WebOrderLineItemID != nil && *purchase.WebOrderLineItemID != 0 {
		id := strconv.FormatInt(*purchase.WebOrderLineItemID, 10)
		w.str("web_order_line_item_id", &id)
	}
	presentBoolString(w, "is_trial_period", purchase.IsTrialPeriod)
	presentBoolString(w, "is_in_intro_offer_period", purchase.IsInIntroOfferPeriod)
	w.close()
}

func presentStr(w *jsonWriter, key string, value *string) {
	if value != nil && *value != "" {
		w.str(key, value)
	}
}

func presentNum(w *jsonWriter, key string, value *int64) {
	if value != nil {
		w.num(key, value)
	}
}

func presentBoolString(w *jsonWriter, key string, value *bool) {
	if value != nil {
		text := strconv.FormatBool(*value)
		w.str(key, &text)
	}
}

// appleDates writes Apple's three renderings of one instant: the GMT
// form, the epoch-millisecond form as a decimal string, and the US
// Pacific form. Apple labels the first "Etc/GMT": that string is part of
// the wire contract, not a description.
func appleDates(w *jsonWriter, prefix string, ms *int64) {
	if ms == nil {
		return
	}
	gmt := formatAppleDate(*ms, 0, "Etc/GMT")
	w.str(prefix, &gmt)
	millis := strconv.FormatInt(*ms, 10)
	w.str(prefix+"_ms", &millis)
	pacific := formatAppleDate(*ms, pacificOffsetSeconds(*ms), "America/Los_Angeles")
	w.str(prefix+"_pst", &pacific)
}
