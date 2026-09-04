package applereceipt

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"
)

// Claims are the decoded JWS payload claims, exactly as Apple sent them.
//
// Numbers arrive as json.Number rather than float64 so that a large
// integer claim survives round-tripping unchanged; the typed payloads
// convert the ones they model.
type Claims map[string]any

// TransactionPayload is a verified JWSTransactionDecodedPayload.
//
// Date claims are epoch milliseconds, as integers, exactly as Apple ships
// them. That is contractual across all ports: converting to time.Time
// loses the raw claim and invites a timezone bug. Only legacy receipt
// attributes (AppReceipt, InAppPurchase) use time.Time.
//
// Claims carries every claim in the payload, including ones this struct
// does not model, so a field Apple adds later is reachable without a
// library update.
type TransactionPayload struct {
	Claims Claims `json:"-"`

	BundleID                    string      `json:"bundleId,omitempty"`
	Environment                 Environment `json:"environment,omitempty"`
	ProductID                   string      `json:"productId,omitempty"`
	TransactionID               string      `json:"transactionId,omitempty"`
	OriginalTransactionID       string      `json:"originalTransactionId,omitempty"`
	WebOrderLineItemID          string      `json:"webOrderLineItemId,omitempty"`
	SubscriptionGroupIdentifier string      `json:"subscriptionGroupIdentifier,omitempty"`
	AppAccountToken             string      `json:"appAccountToken,omitempty"`
	InAppOwnershipType          string      `json:"inAppOwnershipType,omitempty"`
	Type                        string      `json:"type,omitempty"`
	TransactionReason           string      `json:"transactionReason,omitempty"`
	Storefront                  string      `json:"storefront,omitempty"`
	Currency                    string      `json:"currency,omitempty"`
	OfferIdentifier             string      `json:"offerIdentifier,omitempty"`

	// Epoch milliseconds. nil means the claim was absent.
	SignedDate           *int64 `json:"signedDate,omitempty"`
	PurchaseDate         *int64 `json:"purchaseDate,omitempty"`
	OriginalPurchaseDate *int64 `json:"originalPurchaseDate,omitempty"`
	ExpiresDate          *int64 `json:"expiresDate,omitempty"`
	RevocationDate       *int64 `json:"revocationDate,omitempty"`

	Price            *int64 `json:"price,omitempty"`
	Quantity         *int64 `json:"quantity,omitempty"`
	OfferType        *int64 `json:"offerType,omitempty"`
	RevocationReason *int64 `json:"revocationReason,omitempty"`
}

// AppTransactionPayload is a verified AppTransaction. Its environment
// lives in ReceiptType.
//
// Date claims are epoch milliseconds, as in TransactionPayload.
type AppTransactionPayload struct {
	Claims Claims `json:"-"`

	BundleID                   string      `json:"bundleId,omitempty"`
	ReceiptType                Environment `json:"receiptType,omitempty"`
	ApplicationVersion         string      `json:"applicationVersion,omitempty"`
	OriginalApplicationVersion string      `json:"originalApplicationVersion,omitempty"`
	DeviceVerification         string      `json:"deviceVerification,omitempty"`
	DeviceVerificationNonce    string      `json:"deviceVerificationNonce,omitempty"`
	AppTransactionID           string      `json:"appTransactionId,omitempty"`

	AppAppleID *int64 `json:"appAppleId,omitempty"`

	// Epoch milliseconds. nil means the claim was absent.
	ReceiptCreationDate  *int64 `json:"receiptCreationDate,omitempty"`
	OriginalPurchaseDate *int64 `json:"originalPurchaseDate,omitempty"`
	PreorderDate         *int64 `json:"preorderDate,omitempty"`

	VersionExternalIdentifier *int64 `json:"versionExternalIdentifier,omitempty"`
}

// IsActiveAt reports whether the transaction grants entitlement at now:
// not revoked, and — for a subscription — not yet expired.
//
// This reads the signed claims and nothing else. A refund or a renewal
// that happened after the payload was signed is invisible to it; Apple's
// server API is the only source for those (INTENT.md).
func (p *TransactionPayload) IsActiveAt(now time.Time) bool {
	if p == nil {
		return false
	}
	ms := now.UnixMilli()
	if p.RevocationDate != nil && ms >= *p.RevocationDate {
		return false
	}
	if p.ExpiresDate != nil {
		return ms < *p.ExpiresDate
	}
	return true
}

// --- claim reading -------------------------------------------------------

func decodeJSONObject(b []byte) (Claims, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	// Numbers stay exact: a float64 round-trip would quietly corrupt a
	// claim above 2^53, and epoch-millisecond dates are close enough to
	// that ceiling to be worth not thinking about.
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing content after JSON value")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("not a JSON object")
	}
	return Claims(object), nil
}

func (c Claims) str(key string) string {
	if value, ok := c[key].(string); ok {
		return value
	}
	return ""
}

func (c Claims) int64(key string) *int64 {
	number, ok := c[key].(json.Number)
	if !ok {
		return nil
	}
	value, err := number.Int64()
	if err != nil {
		return nil
	}
	return &value
}

func (c Claims) environment(key string) Environment { return Environment(c.str(key)) }

func newTransactionPayload(c Claims) *TransactionPayload {
	return &TransactionPayload{
		Claims:                      c,
		BundleID:                    c.str("bundleId"),
		Environment:                 c.environment("environment"),
		ProductID:                   c.str("productId"),
		TransactionID:               c.str("transactionId"),
		OriginalTransactionID:       c.str("originalTransactionId"),
		WebOrderLineItemID:          c.str("webOrderLineItemId"),
		SubscriptionGroupIdentifier: c.str("subscriptionGroupIdentifier"),
		AppAccountToken:             c.str("appAccountToken"),
		InAppOwnershipType:          c.str("inAppOwnershipType"),
		Type:                        c.str("type"),
		TransactionReason:           c.str("transactionReason"),
		Storefront:                  c.str("storefront"),
		Currency:                    c.str("currency"),
		OfferIdentifier:             c.str("offerIdentifier"),
		SignedDate:                  c.int64("signedDate"),
		PurchaseDate:                c.int64("purchaseDate"),
		OriginalPurchaseDate:        c.int64("originalPurchaseDate"),
		ExpiresDate:                 c.int64("expiresDate"),
		RevocationDate:              c.int64("revocationDate"),
		Price:                       c.int64("price"),
		Quantity:                    c.int64("quantity"),
		OfferType:                   c.int64("offerType"),
		RevocationReason:            c.int64("revocationReason"),
	}
}

func newAppTransactionPayload(c Claims) *AppTransactionPayload {
	return &AppTransactionPayload{
		Claims:                     c,
		BundleID:                   c.str("bundleId"),
		ReceiptType:                c.environment("receiptType"),
		ApplicationVersion:         c.str("applicationVersion"),
		OriginalApplicationVersion: c.str("originalApplicationVersion"),
		DeviceVerification:         c.str("deviceVerification"),
		DeviceVerificationNonce:    c.str("deviceVerificationNonce"),
		AppTransactionID:           c.str("appTransactionId"),
		AppAppleID:                 c.int64("appAppleId"),
		ReceiptCreationDate:        c.int64("receiptCreationDate"),
		OriginalPurchaseDate:       c.int64("originalPurchaseDate"),
		PreorderDate:               c.int64("preorderDate"),
		VersionExternalIdentifier:  c.int64("versionExternalIdentifier"),
	}
}

// signedAtMillis is the instant the payload says it was signed:
// signedDate for transactions, receiptCreationDate for AppTransactions,
// nil when the payload carries neither.
//
// Chain validity is judged here so payloads signed with since-rotated
// certificates keep verifying (PLAN.md §2.1 step 4).
func signedAtMillis(c Claims) *int64 {
	if value := c.int64("signedDate"); value != nil {
		return value
	}
	return c.int64("receiptCreationDate")
}
