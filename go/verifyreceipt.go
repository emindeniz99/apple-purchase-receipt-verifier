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

	// MaxReceiptBytes is the ceiling on a receipt's DECODED size, and it
	// bounds the base64 decode of receipt-data as well as the parse.
	// Zero means DefaultMaxReceiptBytes.
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
	if opts.Environment != EnvironmentProduction && opts.Environment != EnvironmentSandbox {
		return nil, fmt.Errorf(
			"applereceipt: Environment must be %q or %q, got %q",
			EnvironmentProduction, EnvironmentSandbox, opts.Environment)
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

// VerifyReceipt handles one verifyReceipt request body.
//
// It never returns an error: like the real endpoint, every failure is a
// status code in the answer.
func (e *VerifyReceiptEndpoint) VerifyReceipt(request VerifyReceiptRequest) (response VerifyReceiptResponse) {
	// The contract is "never panics", and it is worth more than the
	// contained bug: an endpoint that kills its caller's request is
	// worse than one that answers 21009.
	defer func() {
		if r := recover(); r != nil {
			response = VerifyReceiptResponse{Status: StatusInternal}
		}
	}()

	if request.ReceiptData == "" {
		return VerifyReceiptResponse{Status: StatusMalformed}
	}
	// The decode is bounded by the same ceiling as the parse: this is the
	// hostile-network surface, and a body far above the ceiling must not
	// buy more work than a body at it.
	fields, err := verifyReceiptCore(decodeBase64(request.ReceiptData, e.maxReceiptBytes), e.roots, e.maxReceiptBytes)
	if err != nil {
		reason, ok := ReasonOf(err)
		switch {
		case !ok:
			return VerifyReceiptResponse{Status: StatusInternal}
		case reason == ReasonInvalidReceiptFormat:
			return VerifyReceiptResponse{Status: StatusMalformed}
		default:
			return VerifyReceiptResponse{Status: StatusNotAuthenticated}
		}
	}

	// 21007/21008 routing from the receipt_type attribute, failing closed
	// (PLAN.md D10): only "Production" and "ProductionVPP" count as
	// production. "ProductionSandbox", "ProductionVPPSandbox", "Xcode"
	// and a missing attribute are all non-production. ("Xcode" is listed
	// for completeness: an Xcode receipt is not Apple-signed, so it fails
	// chain verification above and never reaches here.)
	production := fields.ReceiptType == "Production" || fields.ReceiptType == "ProductionVPP"
	if e.environment == EnvironmentProduction && !production {
		return VerifyReceiptResponse{Status: StatusSandboxReceiptOnProduction}
	}
	if e.environment == EnvironmentSandbox && production {
		return VerifyReceiptResponse{Status: StatusProductionReceiptOnSandbox}
	}
	return VerifyReceiptResponse{
		Status:      StatusOK,
		Environment: e.environment,
		Receipt:     e.receiptJSON(fields, e.now()),
	}
}

// VerifyReceiptJSON handles one verifyReceipt request body in its raw
// wire form: the JSON request in, the JSON response out, so an HTTP
// framework's body can be piped through without a DTO in between.
//
// A body that is not a JSON object — unparseable, null, an array, a
// scalar — answers {"status":21002}. Apple has no status code for "that
// wasn't JSON"; 21002 is the closest, and it is what a JSON object with
// no usable receipt-data gets anyway.
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
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return malformedJSON()
	}
	var request VerifyReceiptRequest
	if data, ok := raw["receipt-data"]; ok {
		// receipt-data must be a JSON string. A number, an object or null
		// is a malformed request, not an empty receipt.
		if err := json.Unmarshal(data, &request.ReceiptData); err != nil {
			return malformedJSON()
		}
	}
	if password, ok := raw["password"]; ok {
		_ = json.Unmarshal(password, &request.Password)
	}
	if exclude, ok := raw["exclude-old-transactions"]; ok {
		_ = json.Unmarshal(exclude, &request.ExcludeOldTransactions)
	}
	out, err := json.Marshal(e.VerifyReceipt(request))
	if err != nil {
		return []byte(`{"status":` + strconv.Itoa(StatusInternal) + `}`)
	}
	return out
}

func malformedJSON() []byte {
	return []byte(`{"status":` + strconv.Itoa(StatusMalformed) + `}`)
}

func (e *VerifyReceiptEndpoint) receiptJSON(fields *AppReceipt, requestDate time.Time) map[string]any {
	receipt := map[string]any{}
	putString(receipt, "receipt_type", fields.ReceiptType)
	putString(receipt, "bundle_id", fields.BundleID)
	putString(receipt, "application_version", fields.AppVersion)
	putString(receipt, "original_application_version", fields.OriginalAppVersion)
	e.putDates(receipt, "receipt_creation_date", fields.CreationDate)
	e.putDates(receipt, "request_date", &requestDate)
	e.putDates(receipt, "original_purchase_date", fields.OriginalPurchaseDate)
	e.putDates(receipt, "expiration_date", fields.ExpirationDate)

	inApp := make([]any, 0, len(fields.InAppPurchases))
	for i := range fields.InAppPurchases {
		inApp = append(inApp, e.inAppJSON(&fields.InAppPurchases[i]))
	}
	receipt["in_app"] = inApp
	return receipt
}

func (e *VerifyReceiptEndpoint) inAppJSON(purchase *InAppPurchase) map[string]any {
	entry := map[string]any{}
	if purchase.Quantity != nil {
		entry["quantity"] = strconv.FormatInt(*purchase.Quantity, 10)
	}
	putString(entry, "product_id", purchase.ProductID)
	putString(entry, "transaction_id", purchase.TransactionID)
	putString(entry, "original_transaction_id", purchase.OriginalTransactionID)
	e.putDates(entry, "purchase_date", purchase.PurchaseDate)
	e.putDates(entry, "original_purchase_date", purchase.OriginalPurchaseDate)
	e.putDates(entry, "expires_date", purchase.ExpiresDate)
	e.putDates(entry, "cancellation_date", purchase.CancellationDate)
	if purchase.WebOrderLineItemID != nil {
		entry["web_order_line_item_id"] = strconv.FormatInt(*purchase.WebOrderLineItemID, 10)
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
func (e *VerifyReceiptEndpoint) putDates(target map[string]any, prefix string, at *time.Time) {
	if at == nil {
		return
	}
	target[prefix] = formatAppleDate(*at, time.UTC, "Etc/GMT")
	target[prefix+"_ms"] = strconv.FormatInt(at.UnixMilli(), 10)
	target[prefix+"_pst"] = formatAppleDate(*at, e.pacific, "America/Los_Angeles")
}

func formatAppleDate(at time.Time, location *time.Location, label string) string {
	return at.In(location).Format("2006-01-02 15:04:05") + " " + label
}
