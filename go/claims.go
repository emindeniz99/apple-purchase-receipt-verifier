package applereceipt

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
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
	value, ok := integralMillis(number)
	if !ok {
		return nil
	}
	return &value
}

// int64 bounds as float64. Both are exactly representable, and the upper
// one is the first float above math.MaxInt64, so the test is half-open.
const (
	minInt64AsFloat          = -9223372036854775808.0
	maxInt64ExclusiveAsFloat = 9223372036854775808.0
)

// integralMillis reads a JSON number as an int64 claim.
//
// json.Number.Int64 parses the LITERAL, so it refuses every spelling that
// is not a bare integer: `1722945600000.0` and `1.7229456e12` both fail
// even though the value they name fits comfortably. JSON does not
// distinguish integers from floats, Apple's own encoders are not the only
// thing that produces these payloads, and every other port reads the value
// rather than its spelling -- node `typeof === 'number'`, java
// `canConvertToLong()`, python `isinstance(x, (int, float))`, php a bounded
// float cast (php/tests/JsonNumberClaimTest.php pins all three spellings),
// swift `as? Double`. Reading only the integer spelling made a claim's
// meaning depend on how it was written, and every consequence was in the
// accept direction: an expiresDate spelled with a decimal point read as
// absent, and IsActiveAt treats an absent expiry as no expiry.
//
// So a literal Int64 refuses falls back to the float, which is exactly what
// those ports hold, and is accepted when it is finite and inside the int64
// range. The conversion truncates toward zero, matching java's longValue()
// and php's (int) cast. Outside that envelope -- 1e300, a number past
// MaxInt64 -- the claim is not representable and stays unread, which is the
// case signedAtMillis turns into INVALID_CHAIN.
func integralMillis(number json.Number) (int64, bool) {
	if value, err := number.Int64(); err == nil {
		return value, true
	}
	value, err := number.Float64()
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, false
	}
	if value < minInt64AsFloat || value >= maxInt64ExclusiveAsFloat {
		return 0, false
	}
	return int64(value), true
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
//
// A claim that IS a number but names no instant an int64 can hold -- 1e300,
// say -- is an error rather than a nil: reporting it absent falls through to
// the current-time anchor in the caller, which hands an attacker the instant
// the certificate windows are judged at. An instant no calendar can express
// is inside no window, so the verdict is a chain failure. A date written
// `1722945600000.0` or `1.7229456e12` is not that case and is read like the
// bare integer -- see integralMillis.
func signedAtMillis(c Claims) (*int64, error) {
	for _, key := range [...]string{"signedDate", "receiptCreationDate"} {
		number, ok := c[key].(json.Number)
		if !ok {
			continue
		}
		value, ok := integralMillis(number)
		if !ok {
			return nil, newError(ReasonInvalidChain,
				"payload signing date %s is not a valid instant", number.String())
		}
		return &value, nil
	}
	return nil, nil
}
