package applereceipt

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// VerifyReceiptEndpoint is a drop-in local replacement for Apple's
// deprecated verifyReceipt endpoint: the same request body, the same
// response body, the same status codes — verified offline against pinned
// Apple roots instead of by calling Apple.
//
// Field-by-field fidelity and the unavoidable gaps (fields that exist
// only in Apple's server-side subscription database, such as
// latest_receipt_info and pending_renewal_info) are documented in
// COMPARISON.md.
//
// Like Apple's endpoint, it does NOT check the bundle id: the caller
// compares receipt.bundle_id, exactly as with the real endpoint.
//
// It never returns an error and never panics. Failures are reported
// through the status field, which is the whole point of the wire
// contract.

// Apple status codes this implementation can produce. 21000, 21004,
// 21005, 21006, 21010 and the 21100-21199 range are out of scope
// (COMPARISON.md) and are never returned, and neither is is_retryable.
const (
	// StatusOK — the receipt verified.
	StatusOK = 0
	// StatusMalformed (21002) — the receipt-data property was malformed
	// or missing.
	StatusMalformed = 21002
	// StatusNotAuthenticated (21003) — the receipt could not be
	// authenticated.
	StatusNotAuthenticated = 21003
	// StatusSandboxReceiptOnProduction (21007) — a sandbox receipt was
	// sent to the production environment.
	StatusSandboxReceiptOnProduction = 21007
	// StatusProductionReceiptOnSandbox (21008) — a production receipt was
	// sent to the sandbox environment.
	StatusProductionReceiptOnSandbox = 21008
	// StatusInternal (21009) — internal error.
	StatusInternal = 21009
)

// MaxRequestBytes is the ceiling on a raw request body handed to
// VerifyReceiptBody, VerifyReceiptBodyAt or VerifyReceiptJSON. A larger
// body is ReasonMalformedRequest, status 21002, before it is parsed:
// JSON parsing allocates a multiple of the body, and that happens before
// any verification.
//
// The number is the Java, PHP and Python ports' (1 MiB). It is
// deliberately below DefaultMaxReceiptBytes: the JSON entry point has an
// amplification the pre-decoded entry points do not. The largest genuine
// receipt in the corpus is 106 KB of base64.
const MaxRequestBytes = 1 << 20

// MaxJSONNestingDepth is how many arrays and objects a request body or a
// JWS header or payload may hold open at once. It is counted before the
// JSON is parsed. A verifyReceipt body is a flat object of strings, and
// Apple's JWS headers and payloads nest two levels at most; 64 is the
// Java, PHP and Python ports' number.
const MaxJSONNestingDepth = 64

// VerifyReceiptRequest is Apple's request body.
// https://developer.apple.com/documentation/appstorereceipts/requestbody
type VerifyReceiptRequest struct {
	// ReceiptData is the base64 receipt, as the client sends it.
	ReceiptData string `json:"receipt-data"`
	// Password is accepted for wire compatibility and never read: a
	// shared secret cannot be validated locally (COMPARISON.md).
	Password string `json:"password,omitempty"`
	// ExcludeOldTransactions is accepted for wire compatibility and has
	// no effect: latest_receipt_info is never produced.
	ExcludeOldTransactions bool `json:"exclude-old-transactions,omitempty"`
}

// VerifyReceiptResponse is Apple's response body.
// https://developer.apple.com/documentation/appstorereceipts/responsebody
//
// Status has no omitempty: a successful verification answers status 0,
// and eliding it would produce a body no verifyReceipt client can read.
type VerifyReceiptResponse struct {
	Status      int            `json:"status"`
	Environment Environment    `json:"environment,omitempty"`
	Receipt     map[string]any `json:"receipt,omitempty"`
}

// VerifyReceiptEndpointOptions configures a VerifyReceiptEndpoint.
type VerifyReceiptEndpointOptions struct {
	// TrustedRoots are the pinned anchors. Required, non-empty.
	TrustedRoots []*x509.Certificate

	// Environment is which environment this instance emulates; it drives
	// the 21007/21008 routing. Required, and only Production or Sandbox:
	// Apple has no verifyReceipt host for Xcode or LocalTesting, so the
	// wider Environment type is narrowed here at construction.
	Environment Environment

	// Now is the source of wall-clock time. nil means time.Now. The only
	// thing it drives is the request_date triple — the instant the
	// request was answered. It cannot reach certificate validity.
	Now func() time.Time

	// PacificLocation renders the _pst date fields. nil means
	// time.LoadLocation("America/Los_Angeles").
	//
	// Injectable because the IANA database is a deployment artifact: a
	// FROM scratch or distroless image has no /usr/share/zoneinfo, and a
	// compiled Go binary does not carry $GOROOT/lib/time/zoneinfo.zip
	// either. If the lookup fails, NewVerifyReceiptEndpoint returns an
	// error naming the one-line remedy rather than silently rendering the
	// wrong instant.
	PacificLocation *time.Location

	// MaxReceiptBytes is the ceiling on receipt-data: on the base64
	// string before it is decoded, and on the DER before it is parsed.
	// Zero means DefaultMaxReceiptBytes. A request body is separately
	// capped at MaxRequestBytes, whatever this is set to.
	MaxReceiptBytes int
}

// VerifyReceiptEndpoint answers verifyReceipt request bodies locally.
//
// It is immutable after construction and safe for concurrent use by
// multiple goroutines.
type VerifyReceiptEndpoint struct {
	roots           []*x509.Certificate
	environment     Environment
	now             func() time.Time
	pacific         *time.Location
	maxReceiptBytes int
}

// NewVerifyReceiptEndpoint validates the options and returns an endpoint.
// A configuration mistake is a plain error, never a *VerificationError.
func NewVerifyReceiptEndpoint(opts VerifyReceiptEndpointOptions) (*VerifyReceiptEndpoint, error) {
	if len(opts.TrustedRoots) == 0 {
		return nil, errors.New("applereceipt: TrustedRoots must not be empty")
	}
	for i, root := range opts.TrustedRoots {
		if root == nil {
			return nil, errors.New("applereceipt: TrustedRoots contains a nil certificate at index " + itoa(i))
		}
	}
	if err := checkEndpointEnvironment(opts.Environment); err != nil {
		return nil, err
	}
	if opts.MaxReceiptBytes < 0 {
		return nil, errors.New("applereceipt: MaxReceiptBytes must not be negative")
	}
	pacific := opts.PacificLocation
	if pacific == nil {
		loaded, err := time.LoadLocation("America/Los_Angeles")
		if err != nil {
			return nil, fmt.Errorf("applereceipt: the verifyReceipt endpoint renders _pst dates and "+
				"needs the IANA time zone database, which this binary cannot reach "+
				"(add `import _ \"time/tzdata\"` to your main package, or set "+
				"VerifyReceiptEndpointOptions.PacificLocation): %w", err)
		}
		pacific = loaded
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	maxBytes := opts.MaxReceiptBytes
	if maxBytes == 0 {
		maxBytes = DefaultMaxReceiptBytes
	}
	return &VerifyReceiptEndpoint{
		roots:           append([]*x509.Certificate(nil), opts.TrustedRoots...),
		environment:     opts.Environment,
		now:             now,
		pacific:         pacific,
		maxReceiptBytes: maxBytes,
	}, nil
}

// VerifyReceipt handles one verifyReceipt request body. request_date is
// the endpoint's clock, read once when the call is made.
//
// It never returns an error and never panics: like the real endpoint,
// every failure is a status in the result. Render Apple's response body
// with the result's Response or JSON.
func (e *VerifyReceiptEndpoint) VerifyReceipt(request VerifyReceiptRequest) *VerifyReceiptResult {
	return e.run(nil, func(requestDate time.Time) *VerifyReceiptResult {
		return e.verify(request.ReceiptData, requestDate)
	})
}

// VerifyReceiptAt is VerifyReceipt with request_date set to now instead
// of the endpoint's clock. now reaches request_date and nothing else:
// certificate validity never sees it.
func (e *VerifyReceiptEndpoint) VerifyReceiptAt(request VerifyReceiptRequest, now time.Time) *VerifyReceiptResult {
	return e.run(&now, func(requestDate time.Time) *VerifyReceiptResult {
		return e.verify(request.ReceiptData, requestDate)
	})
}

// VerifyReceiptData verifies a bare base64 receipt, the value a request
// body carries as receipt-data, with no envelope around it. An empty
// string is ReasonMalformedRequest, as a missing receipt-data is.
func (e *VerifyReceiptEndpoint) VerifyReceiptData(receiptData string) *VerifyReceiptResult {
	return e.run(nil, func(requestDate time.Time) *VerifyReceiptResult {
		return e.verify(receiptData, requestDate)
	})
}

// VerifyReceiptDataAt is VerifyReceiptData with request_date set to now
// instead of the endpoint's clock.
func (e *VerifyReceiptEndpoint) VerifyReceiptDataAt(receiptData string, now time.Time) *VerifyReceiptResult {
	return e.run(&now, func(requestDate time.Time) *VerifyReceiptResult {
		return e.verify(receiptData, requestDate)
	})
}

// VerifyReceiptBody handles one verifyReceipt request body in its raw
// wire form, the JSON an HTTP framework hands over.
//
// A body that is not a JSON object (unparseable, null, an array, a
// scalar), that is longer than MaxRequestBytes or nests deeper than
// MaxJSONNestingDepth, or whose receipt-data is not a JSON string, is
// ReasonMalformedRequest, status 21002. Both caps are checked before the
// body is parsed. Apple has no status code for
// "that wasn't JSON"; 21002 is the closest, and it is what a JSON object
// with no usable receipt-data gets anyway.
func (e *VerifyReceiptEndpoint) VerifyReceiptBody(body []byte) *VerifyReceiptResult {
	return e.run(nil, func(requestDate time.Time) *VerifyReceiptResult {
		return e.verifyBody(body, requestDate)
	})
}

// VerifyReceiptBodyAt is VerifyReceiptBody with request_date set to now
// instead of the endpoint's clock.
func (e *VerifyReceiptEndpoint) VerifyReceiptBodyAt(body []byte, now time.Time) *VerifyReceiptResult {
	return e.run(&now, func(requestDate time.Time) *VerifyReceiptResult {
		return e.verifyBody(body, requestDate)
	})
}

// VerifyReceiptJSON handles one verifyReceipt request body in its raw
// wire form: the JSON request in, the JSON response out, so an HTTP
// framework's body can be piped through without a DTO in between. It is
// VerifyReceiptBody(body).JSON().
//
// The output is deterministic: encoding/json sorts object keys, so equal
// inputs serialize to equal bytes.
//
// No http.Handler ships with this library, deliberately. COMPARISON.md
// puts status 21000 out of scope on the grounds that this is a
// body-level API with no HTTP layer, and a handler would have to answer
// questions — which methods, which content types, what body cap, what
// HTTP status accompanies 21002 — that no other port answered. Wire this
// into your own mux in three lines instead.
func (e *VerifyReceiptEndpoint) VerifyReceiptJSON(body []byte) []byte {
	return e.VerifyReceiptBody(body).JSON()
}

// run resolves request_date once (at, or else the endpoint's clock) and
// hands it to verify, turning any panic into ReasonInternalError.
//
// The contract is "never panics", and it is worth more than the
// contained bug: an endpoint that kills its caller's request is worse
// than one that answers 21009. The injected clock is inside the recover
// too, because it is caller code.
func (e *VerifyReceiptEndpoint) run(at *time.Time,
	verify func(requestDate time.Time) *VerifyReceiptResult) (result *VerifyReceiptResult) {
	var requestDate time.Time
	defer func() {
		if r := recover(); r != nil {
			cause, ok := r.(error)
			if !ok {
				cause = fmt.Errorf("panic: %v", r)
			}
			result = e.internalError(cause, requestDate)
		}
	}()
	if at != nil {
		requestDate = *at
	} else {
		requestDate = e.now()
	}
	return verify(requestDate)
}

func (e *VerifyReceiptEndpoint) verifyBody(body []byte, requestDate time.Time) *VerifyReceiptResult {
	if len(body) > MaxRequestBytes {
		return e.failed(newError(ReasonMalformedRequest,
			"the request body exceeds the %d byte limit", MaxRequestBytes), requestDate)
	}
	if jsonNestingExceeds(body, MaxJSONNestingDepth) {
		return e.failed(newError(ReasonMalformedRequest,
			"the request body nests deeper than %d levels", MaxJSONNestingDepth), requestDate)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil || raw == nil {
		return e.failed(newError(ReasonMalformedRequest, "the request body is not a JSON object"), requestDate)
	}
	var receiptData string
	if data, ok := raw["receipt-data"]; ok {
		// receipt-data must be a JSON string. A number, an object or null
		// is a malformed request, not an empty receipt.
		if err := json.Unmarshal(data, &receiptData); err != nil {
			return e.failed(newError(ReasonMalformedRequest, "receipt-data is not a JSON string"), requestDate)
		}
	}
	// password and exclude-old-transactions are accepted for wire
	// compatibility and never read (COMPARISON.md).
	return e.verify(receiptData, requestDate)
}

// verify is the one verification path every entry point ends in.
// requestDate only becomes request_date: certificate validity is judged
// inside verifyReceiptCore, which takes no time input.
func (e *VerifyReceiptEndpoint) verify(receiptData string, requestDate time.Time) *VerifyReceiptResult {
	if receiptData == "" {
		return e.failed(newError(ReasonMalformedRequest, "receipt-data is missing or empty"), requestDate)
	}
	// The string is checked against the ceiling before it is decoded: this
	// is the hostile-network surface, and a receipt-data far above the
	// ceiling must not buy more work than one at it.
	der, err := receiptFromBase64(receiptData, e.maxReceiptBytes)
	var fields *AppReceipt
	if err == nil {
		fields, err = verifyReceiptCore(der, e.roots, e.maxReceiptBytes)
	}
	if err != nil {
		var verr *VerificationError
		if errors.As(err, &verr) && verr != nil {
			return e.failed(verr, requestDate)
		}
		return e.internalError(err, requestDate)
	}
	return &VerifyReceiptResult{
		environment: e.environment,
		pacific:     e.pacific,
		receipt:     fields,
		production:  isProductionReceipt(fields),
		requestDate: requestDate,
	}
}

func (e *VerifyReceiptEndpoint) failed(err *VerificationError, requestDate time.Time) *VerifyReceiptResult {
	return &VerifyReceiptResult{
		environment: e.environment,
		pacific:     e.pacific,
		err:         err,
		requestDate: requestDate,
	}
}

func (e *VerifyReceiptEndpoint) internalError(cause error, requestDate time.Time) *VerifyReceiptResult {
	return e.failed(wrapError(ReasonInternalError, cause, "unexpected error in the verifyReceipt endpoint"), requestDate)
}

// isProductionReceipt is the 21007/21008 routing rule, failing closed
// (PLAN.md D10): only "Production" and "ProductionVPP" count as
// production. "ProductionSandbox", "ProductionVPPSandbox", "Xcode" and a
// missing attribute are all non-production. ("Xcode" is listed for
// completeness: an Xcode receipt is not Apple-signed, so it fails chain
// verification and never gets here.)
func isProductionReceipt(fields *AppReceipt) bool {
	return fields.ReceiptType == "Production" || fields.ReceiptType == "ProductionVPP"
}

func (r *VerifyReceiptResult) receiptJSON(fields *AppReceipt, requestDate time.Time) map[string]any {
	receipt := map[string]any{}
	putString(receipt, "receipt_type", fields.ReceiptType)
	// Apple echoes attribute 1 under both names — its response reference
	// defines adam_id as "See app_item_id" — and as JSON numbers, not as
	// the strings the in-app integers are rendered with.
	if fields.AppItemID != nil {
		receipt["adam_id"] = *fields.AppItemID
		receipt["app_item_id"] = *fields.AppItemID
	}
	putString(receipt, "bundle_id", fields.BundleID)
	putString(receipt, "application_version", fields.AppVersion)
	if fields.DownloadID != nil {
		receipt["download_id"] = *fields.DownloadID
	}
	if fields.VersionExternalIdentifier != nil {
		receipt["version_external_identifier"] = *fields.VersionExternalIdentifier
	}
	putString(receipt, "original_application_version", fields.OriginalAppVersion)
	r.putDates(receipt, "receipt_creation_date", fields.CreationDate)
	r.putDates(receipt, "request_date", &requestDate)
	r.putDates(receipt, "original_purchase_date", fields.OriginalPurchaseDate)
	r.putDates(receipt, "expiration_date", fields.ExpirationDate)

	inApp := make([]any, 0, len(fields.InAppPurchases))
	for i := range fields.InAppPurchases {
		inApp = append(inApp, r.inAppJSON(&fields.InAppPurchases[i]))
	}
	receipt["in_app"] = inApp
	return receipt
}

func (r *VerifyReceiptResult) inAppJSON(purchase *InAppPurchase) map[string]any {
	entry := map[string]any{}
	if purchase.Quantity != nil {
		entry["quantity"] = strconv.FormatInt(*purchase.Quantity, 10)
	}
	putString(entry, "product_id", purchase.ProductID)
	putString(entry, "transaction_id", purchase.TransactionID)
	putString(entry, "original_transaction_id", purchase.OriginalTransactionID)
	r.putDates(entry, "purchase_date", purchase.PurchaseDate)
	r.putDates(entry, "original_purchase_date", purchase.OriginalPurchaseDate)
	r.putDates(entry, "expires_date", purchase.ExpiresDate)
	r.putDates(entry, "cancellation_date", purchase.CancellationDate)
	if purchase.WebOrderLineItemID != nil {
		entry["web_order_line_item_id"] = strconv.FormatInt(*purchase.WebOrderLineItemID, 10)
	}
	if purchase.IsTrialPeriod != nil {
		entry["is_trial_period"] = strconv.FormatBool(*purchase.IsTrialPeriod == 1)
	}
	if purchase.IsInIntroOfferPeriod != nil {
		entry["is_in_intro_offer_period"] = strconv.FormatBool(*purchase.IsInIntroOfferPeriod == 1)
	}
	return entry
}

func putString(target map[string]any, key, value string) {
	if value != "" {
		target[key] = value
	}
}

// putDates writes Apple's three renderings of one instant: the GMT form,
// the epoch-millisecond form as a decimal string, and the US Pacific
// form. Apple labels the first "Etc/GMT" — that string is part of the
// wire contract, not a description.
func (r *VerifyReceiptResult) putDates(target map[string]any, prefix string, at *time.Time) {
	if at == nil {
		return
	}
	target[prefix] = formatAppleDate(*at, time.UTC, "Etc/GMT")
	target[prefix+"_ms"] = strconv.FormatInt(at.UnixMilli(), 10)
	target[prefix+"_pst"] = formatAppleDate(*at, r.pacific, "America/Los_Angeles")
}

func formatAppleDate(at time.Time, location *time.Location, label string) string {
	return at.In(location).Format("2006-01-02 15:04:05") + " " + label
}
