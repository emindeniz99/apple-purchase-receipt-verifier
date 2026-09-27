package applereceipt

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/emindeniz99/apple-purchase-receipt-verifier/go/internal/der"
)

// The legacy receipt payload: the attribute SET inside the CMS envelope.
//
//	SET OF ReceiptAttribute
//	ReceiptAttribute ::= SEQUENCE { type INTEGER, version INTEGER, value OCTET STRING }
//
// occasionally double-wrapped in an extra OCTET STRING (Xcode receipts do
// this).
//
// Decode rules, the same in every port (docs/design/0.7-api.md): a missing
// attribute is nil; the first copy of a known attribute fills its field;
// every attribute that does not end up in a field (an unmodelled type, a
// later copy, a value that does not parse) is kept raw in
// UnknownAttributes, except an empty date string, which means "not set".
// Only an attribute SET, or an attribute, that does not parse makes the
// whole payload unreadable.

// App-level attribute types. 0 and 18 are undocumented but
// community-established, and verifyReceipt response compatibility needs
// both. 1, 15 and 16 are undocumented too: they were established by
// decoding a genuine production receipt and lining its attributes up
// against the answer Apple's verifyReceipt endpoint gives for the same
// receipt (measured 2026-09-21). 1 is the app's App Store item id, which
// Apple echoes as both adam_id and app_item_id; 15 is download_id; 16 is
// version_external_identifier.
const (
	attrReceiptType               int64 = 0
	attrAppItemID                 int64 = 1
	attrBundleID                  int64 = 2
	attrAppVersion                int64 = 3
	attrOpaqueValue               int64 = 4
	attrSHA1Hash                  int64 = 5
	attrCreationDate              int64 = 12
	attrDownloadID                int64 = 15
	attrVersionExternalIdentifier int64 = 16
	attrInApp                     int64 = 17
	attrOriginalPurchaseDate      int64 = 18
	attrOriginalAppVersion        int64 = 19
	attrExpirationDate            int64 = 21
)

// In-app purchase attribute types. 1713 is undocumented, established the
// same way as the app-level ids above (measured 2026-09-21): it is
// is_trial_period.
const (
	iapQuantity             int64 = 1701
	iapProductID            int64 = 1702
	iapTransactionID        int64 = 1703
	iapPurchaseDate         int64 = 1704
	iapOriginalTransaction  int64 = 1705
	iapOriginalPurchaseDate int64 = 1706
	iapExpiresDate          int64 = 1708
	iapWebOrderLineItemID   int64 = 1711
	iapCancellationDate     int64 = 1712
	iapIsTrialPeriod        int64 = 1713
	iapIsInIntroOfferPeriod int64 = 1719
)

// maxAttributeType is 2^31-1.
//
// Attribute types are a 32-bit signed space: every type Apple has ever
// issued is a small number, and a value above this cannot be a real Apple
// attribute type. Ports have to agree on what such a receipt means, so the
// cross-port contract is to reject rather than narrow it onto a sentinel.
const maxAttributeType int64 = 1<<31 - 1

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
}

type receiptAttribute struct {
	kind  int64
	value []byte
}

// readCreationDateMs reads the receipt creation date (attribute 12) the
// only way anything in a payload is read before its signer is trusted:
// the top-level attribute SET is walked shallowly, each entry's type is
// read, and only the value of the FIRST type 12 is decoded.
//
// nil means "judge the chain at the clock": no attribute 12, an empty
// one, one that does not decode, or a walk that fails anywhere. An entry
// the walk cannot read fails the whole read rather than being skipped,
// since that entry might have been the first attribute 12. It never
// panics outward: nothing is trusted yet, so nothing here can blame
// anyone.
func readCreationDateMs(content []byte) (ms *int64) {
	defer func() {
		if recover() != nil {
			ms = nil
		}
	}()
	attributes, err := parseAttributeSet(content)
	if err != nil {
		return nil
	}
	for i := range attributes {
		if attributes[i].kind == attrCreationDate {
			value, ok := decodeReceiptDate(attributes[i].value)
			if !ok {
				return nil
			}
			return value
		}
	}
	return nil
}

// parseReceiptPayload is the full payload parse, run only after the chain
// and the signature have passed.
func parseReceiptPayload(content []byte) (payload *ReceiptPayload, err error) {
	defer func() {
		if r := recover(); r != nil {
			payload = nil
			err = errors.New("panic while reading receipt payload")
		}
	}()
	attributes, err := parseAttributeSet(content)
	if err != nil {
		return nil, err
	}
	receipt := &ReceiptPayload{UnknownAttributes: UnknownAttributes{}, InApp: []InAppPurchase{}}
	seen := make(map[int64]bool, len(attributes))
	for _, attr := range attributes {
		known := isKnownReceiptAttribute(attr.kind)
		if known && seen[attr.kind] {
			keepRaw(receipt.UnknownAttributes, attr)
			continue
		}
		if known {
			seen[attr.kind] = true
		}
		if !decodeReceiptAttribute(receipt, attr) {
			keepRaw(receipt.UnknownAttributes, attr)
		}
	}
	return receipt, nil
}

func isKnownReceiptAttribute(kind int64) bool {
	switch kind {
	case attrReceiptType, attrAppItemID, attrBundleID, attrAppVersion, attrOpaqueValue,
		attrSHA1Hash, attrCreationDate, attrDownloadID, attrVersionExternalIdentifier,
		attrOriginalPurchaseDate, attrOriginalAppVersion, attrExpirationDate:
		return true
	default:
		return false
	}
}

// decodeReceiptAttribute decodes one attribute into receipt's fields. It
// returns false when the attribute did not decode (the caller keeps it
// raw) or is not modelled at all. attrInApp always returns true: a
// purchase that fails to parse is kept raw under 17 by parseInApp itself
// pushing nothing, so the caller's keepRaw call still applies via the
// false return below.
func decodeReceiptAttribute(receipt *ReceiptPayload, attr receiptAttribute) bool {
	switch attr.kind {
	case attrReceiptType:
		value, ok := decodeReceiptString(attr.value)
		if !ok {
			return false
		}
		receipt.ReceiptType = &value
		return true
	case attrAppItemID:
		value, ok := decodeReceiptInteger(attr.value)
		if !ok {
			return false
		}
		receipt.AppItemID = &value
		return true
	case attrBundleID:
		// The octets are a field of their own, kept even when the string
		// does not decode, so they are never kept raw.
		receipt.BundleIDBytes = append([]byte(nil), attr.value...)
		if value, ok := decodeReceiptString(attr.value); ok {
			receipt.BundleID = &value
		}
		return true
	case attrAppVersion:
		value, ok := decodeReceiptString(attr.value)
		if !ok {
			return false
		}
		receipt.ApplicationVersion = &value
		return true
	case attrOpaqueValue:
		receipt.OpaqueValue = append([]byte(nil), attr.value...)
		return true
	case attrSHA1Hash:
		receipt.SHA1Hash = append([]byte(nil), attr.value...)
		return true
	case attrCreationDate:
		value, ok := decodeReceiptDate(attr.value)
		if !ok {
			return false
		}
		receipt.ReceiptCreationDateMs = value
		return true
	case attrDownloadID:
		value, ok := decodeReceiptInteger(attr.value)
		if !ok {
			return false
		}
		receipt.DownloadID = &value
		return true
	case attrVersionExternalIdentifier:
		value, ok := decodeReceiptInteger(attr.value)
		if !ok {
			return false
		}
		receipt.VersionExternalIdentifier = &value
		return true
	case attrInApp:
		purchase, ok := parseInApp(attr.value)
		if !ok {
			return false
		}
		receipt.InApp = append(receipt.InApp, *purchase)
		return true
	case attrOriginalPurchaseDate:
		value, ok := decodeReceiptDate(attr.value)
		if !ok {
			return false
		}
		receipt.OriginalPurchaseDateMs = value
		return true
	case attrOriginalAppVersion:
		value, ok := decodeReceiptString(attr.value)
		if !ok {
			return false
		}
		receipt.OriginalApplicationVersion = &value
		return true
	case attrExpirationDate:
		value, ok := decodeReceiptDate(attr.value)
		if !ok {
			return false
		}
		receipt.ExpirationDateMs = value
		return true
	default:
		return false
	}
}

// parseInApp decodes attribute 17. Anything that stops it from parsing
// (its attribute SET, or one of its attributes) makes the whole attribute
// raw under 17 in the caller (ok false); a value inside it that merely
// does not decode is kept raw under this purchase's own
// UnknownAttributes, exactly as at the top level.
func parseInApp(value []byte) (*InAppPurchase, bool) {
	attributes, err := parseAttributeSet(value)
	if err != nil {
		return nil, false
	}
	purchase := &InAppPurchase{UnknownAttributes: UnknownAttributes{}}
	seen := make(map[int64]bool, len(attributes))
	for _, attr := range attributes {
		known := isKnownInAppAttribute(attr.kind)
		if known && seen[attr.kind] {
			keepRaw(purchase.UnknownAttributes, attr)
			continue
		}
		if known {
			seen[attr.kind] = true
		}
		if !decodeInAppAttribute(purchase, attr) {
			keepRaw(purchase.UnknownAttributes, attr)
		}
	}
	return purchase, true
}

func isKnownInAppAttribute(kind int64) bool {
	switch kind {
	case iapQuantity, iapProductID, iapTransactionID, iapPurchaseDate, iapOriginalTransaction,
		iapOriginalPurchaseDate, iapExpiresDate, iapWebOrderLineItemID, iapCancellationDate,
		iapIsTrialPeriod, iapIsInIntroOfferPeriod:
		return true
	default:
		return false
	}
}

func decodeInAppAttribute(purchase *InAppPurchase, attr receiptAttribute) bool {
	switch attr.kind {
	case iapQuantity:
		value, ok := decodeReceiptInteger(attr.value)
		if !ok {
			return false
		}
		purchase.Quantity = &value
		return true
	case iapProductID:
		value, ok := decodeReceiptString(attr.value)
		if !ok {
			return false
		}
		purchase.ProductID = &value
		return true
	case iapTransactionID:
		value, ok := decodeReceiptString(attr.value)
		if !ok {
			return false
		}
		purchase.TransactionID = &value
		return true
	case iapPurchaseDate:
		value, ok := decodeReceiptDate(attr.value)
		if !ok {
			return false
		}
		purchase.PurchaseDateMs = value
		return true
	case iapOriginalTransaction:
		value, ok := decodeReceiptString(attr.value)
		if !ok {
			return false
		}
		purchase.OriginalTransactionID = &value
		return true
	case iapOriginalPurchaseDate:
		value, ok := decodeReceiptDate(attr.value)
		if !ok {
			return false
		}
		purchase.OriginalPurchaseDateMs = value
		return true
	case iapExpiresDate:
		value, ok := decodeReceiptDate(attr.value)
		if !ok {
			return false
		}
		purchase.ExpiresDateMs = value
		return true
	case iapWebOrderLineItemID:
		value, ok := decodeReceiptInteger(attr.value)
		if !ok {
			return false
		}
		purchase.WebOrderLineItemID = &value
		return true
	case iapCancellationDate:
		value, ok := decodeReceiptDate(attr.value)
		if !ok {
			return false
		}
		purchase.CancellationDateMs = value
		return true
	case iapIsTrialPeriod:
		value, ok := decodeReceiptInteger(attr.value)
		if !ok {
			return false
		}
		flag := value != 0
		purchase.IsTrialPeriod = &flag
		return true
	case iapIsInIntroOfferPeriod:
		value, ok := decodeReceiptInteger(attr.value)
		if !ok {
			return false
		}
		flag := value != 0
		purchase.IsInIntroOfferPeriod = &flag
		return true
	default:
		return false
	}
}

func keepRaw(into UnknownAttributes, attr receiptAttribute) {
	into[attr.kind] = append(into[attr.kind], append([]byte(nil), attr.value...))
}

// parseAttributeSet reads the SET OF ReceiptAttribute at b (unwrapping one
// Xcode-style extra OCTET STRING when present), a failure of which is
// always fatal to whatever is reading it: the caller decides what that
// means (ReasonMalformed before the signature, ReasonUnreadablePayload
// after it).
func parseAttributeSet(b []byte) ([]receiptAttribute, error) {
	node, err := der.Parse(b)
	if err != nil {
		return nil, err
	}
	if der.IsOctetString(node) {
		// Xcode receipts double-wrap the payload in an extra OCTET STRING.
		node, err = der.Parse(der.OctetValue(node))
		if err != nil {
			return nil, err
		}
	}
	if node.Tag != der.TagSet {
		return nil, errors.New("receipt payload is not an ASN.1 SET")
	}
	attributes := make([]receiptAttribute, 0, len(node.Children))
	for _, child := range node.Children {
		attr, ok := parseOneAttribute(child)
		if !ok {
			return nil, errors.New("malformed receipt attribute")
		}
		attributes = append(attributes, attr)
	}
	return attributes, nil
}

// parseOneAttribute reads one ReceiptAttribute ::= SEQUENCE { type
// INTEGER, version INTEGER, value OCTET STRING, ... }. Fields after the
// third are tolerated, so a field Apple appends later does not break
// parsing; the version is not read, but when it is tagged INTEGER its
// encoding must still be well-formed DER.
func parseOneAttribute(node *der.Node) (receiptAttribute, bool) {
	if node.Tag != der.TagSequence || len(node.Children) < 3 {
		return receiptAttribute{}, false
	}
	typeNode, versionNode, valueNode := node.Children[0], node.Children[1], node.Children[2]
	if typeNode.Tag != der.TagInteger || !der.IsOctetString(valueNode) {
		return receiptAttribute{}, false
	}
	if versionNode.Tag == der.TagInteger {
		if _, ok := strictInteger(versionNode.Contents); !ok {
			return receiptAttribute{}, false
		}
	}
	kindValue, ok := strictInteger(typeNode.Contents)
	if !ok || kindValue < 0 || kindValue > maxAttributeType {
		return receiptAttribute{}, false
	}
	return receiptAttribute{kind: kindValue, value: der.OctetValue(valueNode)}, true
}

// strictInteger reads DER INTEGER contents strictly: non-empty, at most 8
// octets (so the value fits an int64), and minimally encoded (X.690
// §8.3.2: the first nine bits are never all zero or all one). An empty
// INTEGER or one with a redundant leading octet is refused rather than
// accepted with padding removed.
func strictInteger(contents []byte) (int64, bool) {
	if len(contents) == 0 || len(contents) > 8 {
		return 0, false
	}
	if len(contents) > 1 {
		first, second := contents[0], contents[1]
		if (first == 0x00 && second&0x80 == 0) || (first == 0xff && second&0x80 != 0) {
			return 0, false
		}
	}
	var value int64
	if contents[0]&0x80 != 0 {
		value = -1
	}
	for _, b := range contents {
		value = (value << 8) | int64(b)
	}
	return value, true
}

// decodeReceiptInteger decodes a known attribute's value as a DER
// INTEGER, negative values included: an ASN.1 INTEGER in hostile input
// can be negative, and the decoder reports what is there.
func decodeReceiptInteger(value []byte) (int64, bool) {
	node, err := der.Parse(value)
	if err != nil || node.Tag != der.TagInteger {
		return 0, false
	}
	return strictInteger(node.Contents)
}

// decodeReceiptString decodes a UTF8String or IA5String, the two string
// types Apple's receipts use. A UTF8String must be valid UTF-8; an
// IA5String must be ASCII, as IA5 is: a byte at or above 0x80 does not
// parse (owner, 2026-09-27), rather than being read as Latin-1.
func decodeReceiptString(value []byte) (string, bool) {
	node, err := der.Parse(value)
	if err != nil {
		return "", false
	}
	switch node.Tag {
	case der.TagUTF8String:
		if !utf8.Valid(node.Contents) {
			return "", false
		}
		return string(node.Contents), true
	case der.TagIA5String:
		for _, b := range node.Contents {
			if b >= 0x80 {
				return "", false
			}
		}
		return string(node.Contents), true
	default:
		return "", false
	}
}

// decodeReceiptDate decodes a date in an IA5String or UTF8String, as
// epoch milliseconds. An empty string is (nil, true): Apple writes an
// unset date that way, so it is not kept raw. Anything else must be
// exactly YYYY-MM-DDTHH:MM:SSZ; anything that does not decode is
// (nil, false), so the caller keeps it raw.
func decodeReceiptDate(value []byte) (*int64, bool) {
	text, ok := decodeReceiptString(value)
	if !ok {
		return nil, false
	}
	if text == "" {
		return nil, true
	}
	ms, ok := parseReceiptDateMs(text)
	if !ok {
		return nil, false
	}
	return &ms, true
}

// parseReceiptDateMs parses exactly YYYY-MM-DDTHH:MM:SSZ: a four-digit
// year 0000 to 9999, uppercase T and Z, a real calendar date (leap years
// included), hours 00 to 23, minutes and seconds 00 to 59, no fraction and
// no offset (owner, 2026-09-27). Every port reads a receipt date with this
// one grammar, so one receipt decodes, and its chain is judged, the same
// everywhere.
func parseReceiptDateMs(text string) (int64, bool) {
	if len(text) != 20 {
		return 0, false
	}
	if text[4] != '-' || text[7] != '-' || text[10] != 'T' || text[13] != ':' ||
		text[16] != ':' || text[19] != 'Z' {
		return 0, false
	}
	digits := func(from, count int) (int, bool) {
		value := 0
		for i := from; i < from+count; i++ {
			c := text[i]
			if c < '0' || c > '9' {
				return 0, false
			}
			value = value*10 + int(c-'0')
		}
		return value, true
	}
	year, ok1 := digits(0, 4)
	month, ok2 := digits(5, 2)
	day, ok3 := digits(8, 2)
	hour, ok4 := digits(11, 2)
	minute, ok5 := digits(14, 2)
	second, ok6 := digits(17, 2)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
		return 0, false
	}
	if month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month) ||
		hour > 23 || minute > 59 || second > 59 {
		return 0, false
	}
	return time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC).UnixMilli(), true
}

func isLeapYear(year int) bool {
	return year%4 == 0 && (year%100 != 0 || year%400 == 0)
}

func daysInMonth(year, month int) int {
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		if isLeapYear(year) {
			return 29
		}
		return 28
	default:
		return 0
	}
}

// --- canonical JSON --------------------------------------------------------

// ToJSON is the canonical JSON every port produces byte for byte
// (docs/design/0.7-api.md, Canonical form): the keys below in this order,
// no whitespace, null for a missing field, 64-bit ids as strings, bytes as
// padded standard base64, unknown_attributes keys in ascending numeric
// order, and strings escaped exactly as ECMAScript JSON.stringify escapes
// them.
//
// receipt_type, app_item_id, bundle_id, bundle_id_bytes,
// application_version, opaque_value, sha1_hash, receipt_creation_date_ms,
// download_id, version_external_identifier, in_app,
// original_purchase_date_ms, original_application_version,
// expiration_date_ms, unknown_attributes.
func (r *ReceiptPayload) ToJSON() string {
	var b strings.Builder
	b.Grow(512 + 512*len(r.InApp))
	w := newJSONWriter(&b)
	w.str("receipt_type", r.ReceiptType)
	w.id("app_item_id", r.AppItemID)
	w.str("bundle_id", r.BundleID)
	w.bytesValue("bundle_id_bytes", r.BundleIDBytes)
	w.str("application_version", r.ApplicationVersion)
	w.bytesValue("opaque_value", r.OpaqueValue)
	w.bytesValue("sha1_hash", r.SHA1Hash)
	w.num("receipt_creation_date_ms", r.ReceiptCreationDateMs)
	w.id("download_id", r.DownloadID)
	w.id("version_external_identifier", r.VersionExternalIdentifier)
	w.arrayStart("in_app")
	for i := range r.InApp {
		if i > 0 {
			b.WriteByte(',')
		}
		r.InApp[i].writeJSON(&b)
	}
	w.arrayEnd()
	w.num("original_purchase_date_ms", r.OriginalPurchaseDateMs)
	w.str("original_application_version", r.OriginalApplicationVersion)
	w.num("expiration_date_ms", r.ExpirationDateMs)
	w.attributes("unknown_attributes", r.UnknownAttributes)
	w.close()
	return b.String()
}

// String is ToJSON.
func (r *ReceiptPayload) String() string { return r.ToJSON() }

func (p *InAppPurchase) writeJSON(out *strings.Builder) {
	w := newJSONWriter(out)
	w.num("quantity", p.Quantity)
	w.str("product_id", p.ProductID)
	w.str("transaction_id", p.TransactionID)
	w.num("purchase_date_ms", p.PurchaseDateMs)
	w.str("original_transaction_id", p.OriginalTransactionID)
	w.num("original_purchase_date_ms", p.OriginalPurchaseDateMs)
	w.num("expires_date_ms", p.ExpiresDateMs)
	w.id("web_order_line_item_id", p.WebOrderLineItemID)
	w.num("cancellation_date_ms", p.CancellationDateMs)
	w.boolean("is_trial_period", p.IsTrialPeriod)
	w.boolean("is_in_intro_offer_period", p.IsInIntroOfferPeriod)
	w.attributes("unknown_attributes", p.UnknownAttributes)
	w.close()
}
