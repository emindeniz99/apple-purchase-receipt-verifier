package applereceipt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
)

// The legacy receipt payload the core hands back, in the Go types 0.7
// defines. aprv.wasm reads the receipt and writes the payload as JSON
// (docs/design/0.7-api.md, "Our JSON"); this file holds the types callers
// see, the JSON shapes that go both ways, and nothing that reads a
// receipt.

// UnknownAttributes maps an attribute type to its raw value octets, kept
// exactly as they sit in the receipt, in receipt order.
type UnknownAttributes map[int64][][]byte

// InAppPurchase is one in-app purchase from a legacy app receipt
// (attribute 17). A nil field means the attribute was absent or did not
// decode; ReceiptPayload.UnknownAttributes (here, this purchase's own
// UnknownAttributes) says which.
type InAppPurchase struct {
	Quantity               *int64  // 1701
	ProductID              *string // 1702
	TransactionID          *string // 1703
	PurchaseDateMs         *int64  // 1704
	OriginalTransactionID  *string // 1705
	OriginalPurchaseDateMs *int64  // 1706
	ExpiresDateMs          *int64  // 1708
	WebOrderLineItemID     *int64  // 1711
	CancellationDateMs     *int64  // 1712
	// IsTrialPeriod is attribute 1713: 0 is false, any other value true.
	IsTrialPeriod *bool
	// IsInIntroOfferPeriod is attribute 1719: 0 is false, any other value
	// true.
	IsInIntroOfferPeriod *bool
	// UnknownAttributes holds every attribute of this purchase that did
	// not end up in a field above.
	UnknownAttributes UnknownAttributes
}

// ReceiptPayload is a verified legacy app receipt.
//
// Only a payload returned by Verifier.VerifyReceipt should be trusted;
// nothing here is meaningful before that returns without an error. Every
// byte slice is a fresh copy, never a view into the caller's input
// buffer.
//
// Dates are epoch milliseconds, UTC, with an Ms suffix; receipt dates
// carry whole seconds, so the last three digits are always 000. The
// 64-bit ids are int64: an ASN.1 INTEGER in hostile input can be
// negative, and the decoder reports what is there.
type ReceiptPayload struct {
	ReceiptType *string // 0
	AppItemID   *int64  // 1
	BundleID    *string // 2
	// BundleIDBytes is attribute 2's value octets exactly as they sit in
	// the receipt: the input to Apple's device-hash formula, together
	// with OpaqueValue and SHA1Hash.
	BundleIDBytes              []byte
	ApplicationVersion         *string         // 3
	OpaqueValue                []byte          // 4
	SHA1Hash                   []byte          // 5
	ReceiptCreationDateMs      *int64          // 12
	DownloadID                 *int64          // 15
	VersionExternalIdentifier  *int64          // 16
	InApp                      []InAppPurchase // 17, one entry per copy
	OriginalPurchaseDateMs     *int64          // 18
	OriginalApplicationVersion *string         // 19
	ExpirationDateMs           *int64          // 21
	// UnknownAttributes holds every attribute that did not end up in a
	// field above.
	UnknownAttributes UnknownAttributes
	// Environment is the environment ReceiptType names, as the verifier
	// read it: "Production" and "ProductionVPP" are EnvironmentProduction,
	// "ProductionSandbox" and "ProductionVPPSandbox" EnvironmentSandbox,
	// anything else ("Xcode", a missing value) nil. It states what Apple's
	// value means and decides nothing, and ToJSON does not write it.
	Environment *Environment
}

// --- JSON ------------------------------------------------------------------

// receiptJSON and inAppJSON are the shapes ToJSON hands to encoding/json.
// A nil pointer is written as null, never omitted; []byte is written as
// padded standard base64.
type receiptJSON struct {
	ReceiptType                *string             `json:"receipt_type"`
	AppItemID                  *string             `json:"app_item_id"`
	BundleID                   *string             `json:"bundle_id"`
	BundleIDBytes              []byte              `json:"bundle_id_bytes"`
	ApplicationVersion         *string             `json:"application_version"`
	OpaqueValue                []byte              `json:"opaque_value"`
	SHA1Hash                   []byte              `json:"sha1_hash"`
	ReceiptCreationDateMs      *int64              `json:"receipt_creation_date_ms"`
	DownloadID                 *string             `json:"download_id"`
	VersionExternalIdentifier  *string             `json:"version_external_identifier"`
	InApp                      []inAppJSON         `json:"in_app"`
	OriginalPurchaseDateMs     *int64              `json:"original_purchase_date_ms"`
	OriginalApplicationVersion *string             `json:"original_application_version"`
	ExpirationDateMs           *int64              `json:"expiration_date_ms"`
	UnknownAttributes          map[string][]string `json:"unknown_attributes"`
}

type inAppJSON struct {
	Quantity               *int64              `json:"quantity"`
	ProductID              *string             `json:"product_id"`
	TransactionID          *string             `json:"transaction_id"`
	PurchaseDateMs         *int64              `json:"purchase_date_ms"`
	OriginalTransactionID  *string             `json:"original_transaction_id"`
	OriginalPurchaseDateMs *int64              `json:"original_purchase_date_ms"`
	ExpiresDateMs          *int64              `json:"expires_date_ms"`
	WebOrderLineItemID     *string             `json:"web_order_line_item_id"`
	CancellationDateMs     *int64              `json:"cancellation_date_ms"`
	IsTrialPeriod          *bool               `json:"is_trial_period"`
	IsInIntroOfferPeriod   *bool               `json:"is_in_intro_offer_period"`
	UnknownAttributes      map[string][]string `json:"unknown_attributes"`
}

// idJSON is a 64-bit id as a decimal string, so JavaScript readers do not
// round it.
func idJSON(value *int64) *string {
	if value == nil {
		return nil
	}
	text := strconv.FormatInt(*value, 10)
	return &text
}

// attributesJSON keys each type by its decimal string, the values base64
// in receipt order. Never nil, so an empty set is {} rather than null.
func attributesJSON(attrs UnknownAttributes) map[string][]string {
	out := make(map[string][]string, len(attrs))
	for attributeType, values := range attrs {
		encoded := make([]string, len(values))
		for i, value := range values {
			encoded[i] = base64.StdEncoding.EncodeToString(value)
		}
		out[strconv.FormatInt(attributeType, 10)] = encoded
	}
	return out
}

// ToJSON is this payload as JSON, for logging and storage
// (docs/design/0.7-api.md, "Our JSON"). Every port writes the same value;
// the bytes may differ. null for a missing field, 64-bit ids as strings,
// bytes as padded standard base64, dates as epoch-millisecond numbers.
//
// receipt_type, app_item_id, bundle_id, bundle_id_bytes,
// application_version, opaque_value, sha1_hash, receipt_creation_date_ms,
// download_id, version_external_identifier, in_app,
// original_purchase_date_ms, original_application_version,
// expiration_date_ms, unknown_attributes.
func (r *ReceiptPayload) ToJSON() string {
	inApp := make([]inAppJSON, len(r.InApp))
	for i := range r.InApp {
		inApp[i] = r.InApp[i].jsonValue()
	}
	// Marshal cannot fail on strings, integers, booleans, slices and
	// string-keyed maps.
	out, _ := json.Marshal(receiptJSON{
		ReceiptType:                r.ReceiptType,
		AppItemID:                  idJSON(r.AppItemID),
		BundleID:                   r.BundleID,
		BundleIDBytes:              r.BundleIDBytes,
		ApplicationVersion:         r.ApplicationVersion,
		OpaqueValue:                r.OpaqueValue,
		SHA1Hash:                   r.SHA1Hash,
		ReceiptCreationDateMs:      r.ReceiptCreationDateMs,
		DownloadID:                 idJSON(r.DownloadID),
		VersionExternalIdentifier:  idJSON(r.VersionExternalIdentifier),
		InApp:                      inApp,
		OriginalPurchaseDateMs:     r.OriginalPurchaseDateMs,
		OriginalApplicationVersion: r.OriginalApplicationVersion,
		ExpirationDateMs:           r.ExpirationDateMs,
		UnknownAttributes:          attributesJSON(r.UnknownAttributes),
	})
	return string(out)
}

func (p *InAppPurchase) jsonValue() inAppJSON {
	return inAppJSON{
		Quantity:               p.Quantity,
		ProductID:              p.ProductID,
		TransactionID:          p.TransactionID,
		PurchaseDateMs:         p.PurchaseDateMs,
		OriginalTransactionID:  p.OriginalTransactionID,
		OriginalPurchaseDateMs: p.OriginalPurchaseDateMs,
		ExpiresDateMs:          p.ExpiresDateMs,
		WebOrderLineItemID:     idJSON(p.WebOrderLineItemID),
		CancellationDateMs:     p.CancellationDateMs,
		IsTrialPeriod:          p.IsTrialPeriod,
		IsInIntroOfferPeriod:   p.IsInIntroOfferPeriod,
		UnknownAttributes:      attributesJSON(p.UnknownAttributes),
	}
}

// receiptFromJSON reads the payload aprv.wasm wrote for a verified receipt,
// with the environment the answer states beside it. It accepts exactly the
// shape 0.7 defines: a member it does not know, a value of the wrong type,
// an id that is not a decimal int64, or bytes that are not base64 is an
// answer this wrapper cannot use, never a payload with something missing.
// Nothing here reads a receipt.
func receiptFromJSON(raw []byte, environment *Environment) (*ReceiptPayload, error) {
	var wire receiptJSON
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return nil, err
	}
	var err error
	out := &ReceiptPayload{
		ReceiptType:                wire.ReceiptType,
		BundleID:                   wire.BundleID,
		BundleIDBytes:              wire.BundleIDBytes,
		ApplicationVersion:         wire.ApplicationVersion,
		OpaqueValue:                wire.OpaqueValue,
		SHA1Hash:                   wire.SHA1Hash,
		ReceiptCreationDateMs:      wire.ReceiptCreationDateMs,
		OriginalPurchaseDateMs:     wire.OriginalPurchaseDateMs,
		OriginalApplicationVersion: wire.OriginalApplicationVersion,
		ExpirationDateMs:           wire.ExpirationDateMs,
		Environment:                environment,
	}
	if out.AppItemID, err = idFromJSON("app_item_id", wire.AppItemID); err != nil {
		return nil, err
	}
	if out.DownloadID, err = idFromJSON("download_id", wire.DownloadID); err != nil {
		return nil, err
	}
	if out.VersionExternalIdentifier, err = idFromJSON("version_external_identifier", wire.VersionExternalIdentifier); err != nil {
		return nil, err
	}
	if out.UnknownAttributes, err = attributesFromJSON(wire.UnknownAttributes); err != nil {
		return nil, err
	}
	for i := range wire.InApp {
		purchase, err := wire.InApp[i].purchase()
		if err != nil {
			return nil, fmt.Errorf("in_app[%d]: %w", i, err)
		}
		out.InApp = append(out.InApp, purchase)
	}
	return out, nil
}

func (w *inAppJSON) purchase() (InAppPurchase, error) {
	out := InAppPurchase{
		Quantity:               w.Quantity,
		ProductID:              w.ProductID,
		TransactionID:          w.TransactionID,
		PurchaseDateMs:         w.PurchaseDateMs,
		OriginalTransactionID:  w.OriginalTransactionID,
		OriginalPurchaseDateMs: w.OriginalPurchaseDateMs,
		ExpiresDateMs:          w.ExpiresDateMs,
		CancellationDateMs:     w.CancellationDateMs,
		IsTrialPeriod:          w.IsTrialPeriod,
		IsInIntroOfferPeriod:   w.IsInIntroOfferPeriod,
	}
	var err error
	if out.WebOrderLineItemID, err = idFromJSON("web_order_line_item_id", w.WebOrderLineItemID); err != nil {
		return out, err
	}
	out.UnknownAttributes, err = attributesFromJSON(w.UnknownAttributes)
	return out, err
}

// idFromJSON reads a 64-bit id, which the wire writes as a decimal string
// so JavaScript readers do not round it.
func idFromJSON(name string, text *string) (*int64, error) {
	if text == nil {
		return nil, nil
	}
	value, err := strconv.ParseInt(*text, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%s is not a decimal 64-bit integer", name)
	}
	return &value, nil
}

// attributesFromJSON reads {"<decimal type>": ["<base64>", ...]}, values in
// receipt order. The result is never nil, as the decoded payload's map
// never was.
func attributesFromJSON(wire map[string][]string) (UnknownAttributes, error) {
	out := make(UnknownAttributes, len(wire))
	for key, values := range wire {
		kind, err := strconv.ParseInt(key, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("unknown_attributes key %q is not a decimal integer", key)
		}
		decoded := make([][]byte, len(values))
		for i, value := range values {
			if decoded[i], err = base64.StdEncoding.DecodeString(value); err != nil {
				return nil, fmt.Errorf("unknown_attributes[%s][%d] is not base64", key, i)
			}
		}
		out[kind] = decoded
	}
	return out, nil
}
