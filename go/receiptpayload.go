package applereceipt

import (
	"bytes"
	"time"

	"github.com/emindeniz99/apple-purchase-receipt-verifier/go/internal/der"
)

// The receipt payload attribute grammar (Apple, "Validating receipts on
// the device"):
//
//	ReceiptAttribute ::= SEQUENCE { type INTEGER, version INTEGER, value OCTET STRING }
//
// inside a SET OF, occasionally double-wrapped in an extra OCTET STRING
// (Xcode receipts do this).

// App-level attribute types. 0 and 18 are undocumented but
// community-established, and verifyReceipt response compatibility needs
// both.
const (
	attrReceiptType          int64 = 0
	attrBundleID             int64 = 2
	attrAppVersion           int64 = 3
	attrOpaqueValue          int64 = 4
	attrSHA1Hash             int64 = 5
	attrCreationDate         int64 = 12
	attrInApp                int64 = 17
	attrOriginalPurchaseDate int64 = 18
	attrOriginalAppVersion   int64 = 19
	attrExpirationDate       int64 = 21
)

// In-app purchase attribute types.
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
	iapIsInIntroOfferPeriod int64 = 1719
)

// maxAttributeType is 2^31-1.
//
// Attribute types are a 32-bit signed space: every type Apple has ever
// issued is a small number, and a value above this cannot be a real Apple
// attribute type. Ports have to agree on what such a receipt means, and
// mapping it onto a sentinel (-1) collides every out-of-range type into
// one bucket keyed by a value that is not a type — so the cross-port
// contract is to reject. Attribute *values* keep the wider range:
// web_order_line_item_id is genuinely a seven-byte integer.
const maxAttributeType int64 = 1<<31 - 1

// InAppPurchase is one in-app purchase from a legacy app receipt
// (attribute 17).
type InAppPurchase struct {
	// UnknownAttributes holds attribute types this library does not
	// model, keyed by type, in encounter order with duplicates preserved
	// (PLAN.md D10 — forward compatibility). The values are the raw
	// signature-covered value octets, undecoded.
	UnknownAttributes map[int64][][]byte `json:"unknownAttributes"`

	Quantity              *int64     `json:"quantity,omitempty"`
	ProductID             string     `json:"productId,omitempty"`
	TransactionID         string     `json:"transactionId,omitempty"`
	OriginalTransactionID string     `json:"originalTransactionId,omitempty"`
	PurchaseDate          *time.Time `json:"purchaseDate,omitempty"`
	OriginalPurchaseDate  *time.Time `json:"originalPurchaseDate,omitempty"`
	ExpiresDate           *time.Time `json:"expiresDate,omitempty"`
	CancellationDate      *time.Time `json:"cancellationDate,omitempty"`
	WebOrderLineItemID    *int64     `json:"webOrderLineItemId,omitempty"`
	IsInIntroOfferPeriod  *int64     `json:"isInIntroOfferPeriod,omitempty"`
}

// AppReceipt is a verified legacy app receipt.
//
// Only a receipt returned by ReceiptVerifier or VerifyReceiptCore should
// be trusted; nothing here is meaningful before those return without an
// error.
//
// Every byte slice is a fresh copy, never a view into the caller's input
// buffer: a caller that reuses its receipt buffer must not be able to
// mutate an already-verified receipt.
type AppReceipt struct {
	// UnknownAttributes holds attribute types this library does not
	// model (PLAN.md D10). See InAppPurchase.UnknownAttributes.
	UnknownAttributes map[int64][][]byte `json:"unknownAttributes"`

	// ReceiptType is attribute 0, e.g. "Production", "ProductionSandbox"
	// (undocumented by Apple; drives the endpoint's 21007/21008 routing).
	ReceiptType string `json:"receiptType,omitempty"`
	BundleID    string `json:"bundleId,omitempty"`
	// BundleIDBytes is the raw DER of attribute 2 — the exact bytes the
	// device-hash check feeds to SHA-1.
	BundleIDBytes []byte `json:"bundleIdBytes,omitempty"`
	AppVersion    string `json:"appVersion,omitempty"`
	OpaqueValue   []byte `json:"opaqueValue,omitempty"`
	SHA1Hash      []byte `json:"sha1Hash,omitempty"`

	CreationDate *time.Time `json:"creationDate,omitempty"`
	// OriginalPurchaseDate is attribute 18 (undocumented).
	OriginalPurchaseDate *time.Time `json:"originalPurchaseDate,omitempty"`
	OriginalAppVersion   string     `json:"originalAppVersion,omitempty"`
	ExpirationDate       *time.Time `json:"expirationDate,omitempty"`

	InAppPurchases []InAppPurchase `json:"inAppPurchases"`
}

type receiptAttribute struct {
	kind  int64
	value []byte
}

func parseReceiptPayload(content []byte) (*AppReceipt, error) {
	attributes, err := parseAttributeSet(content)
	if err != nil {
		return nil, err
	}
	receipt := &AppReceipt{
		UnknownAttributes: map[int64][][]byte{},
		InAppPurchases:    []InAppPurchase{},
	}
	for _, attr := range attributes {
		switch attr.kind {
		case attrReceiptType:
			if receipt.ReceiptType, err = decodeString(attr.value); err != nil {
				return nil, err
			}
		case attrBundleID:
			if receipt.BundleID, err = decodeString(attr.value); err != nil {
				return nil, err
			}
			receipt.BundleIDBytes = bytes.Clone(attr.value)
		case attrAppVersion:
			if receipt.AppVersion, err = decodeString(attr.value); err != nil {
				return nil, err
			}
		case attrOpaqueValue:
			receipt.OpaqueValue = bytes.Clone(attr.value)
		case attrSHA1Hash:
			receipt.SHA1Hash = bytes.Clone(attr.value)
		case attrCreationDate:
			if receipt.CreationDate, err = decodeDate(attr.value); err != nil {
				return nil, err
			}
		case attrInApp:
			purchase, err := parseInApp(attr.value)
			if err != nil {
				return nil, err
			}
			receipt.InAppPurchases = append(receipt.InAppPurchases, *purchase)
		case attrOriginalPurchaseDate:
			if receipt.OriginalPurchaseDate, err = decodeDate(attr.value); err != nil {
				return nil, err
			}
		case attrOriginalAppVersion:
			if receipt.OriginalAppVersion, err = decodeString(attr.value); err != nil {
				return nil, err
			}
		case attrExpirationDate:
			if receipt.ExpirationDate, err = decodeDate(attr.value); err != nil {
				return nil, err
			}
		default:
			recordUnknown(receipt.UnknownAttributes, attr)
		}
	}
	return receipt, nil
}

func parseInApp(value []byte) (*InAppPurchase, error) {
	attributes, err := parseAttributeSet(value)
	if err != nil {
		return nil, err
	}
	purchase := &InAppPurchase{UnknownAttributes: map[int64][][]byte{}}
	for _, attr := range attributes {
		switch attr.kind {
		case iapQuantity:
			if purchase.Quantity, err = decodeInteger(attr.value); err != nil {
				return nil, err
			}
		case iapProductID:
			if purchase.ProductID, err = decodeString(attr.value); err != nil {
				return nil, err
			}
		case iapTransactionID:
			if purchase.TransactionID, err = decodeString(attr.value); err != nil {
				return nil, err
			}
		case iapPurchaseDate:
			if purchase.PurchaseDate, err = decodeDate(attr.value); err != nil {
				return nil, err
			}
		case iapOriginalTransaction:
			if purchase.OriginalTransactionID, err = decodeString(attr.value); err != nil {
				return nil, err
			}
		case iapOriginalPurchaseDate:
			if purchase.OriginalPurchaseDate, err = decodeDate(attr.value); err != nil {
				return nil, err
			}
		case iapExpiresDate:
			if purchase.ExpiresDate, err = decodeDate(attr.value); err != nil {
				return nil, err
			}
		case iapWebOrderLineItemID:
			if purchase.WebOrderLineItemID, err = decodeInteger(attr.value); err != nil {
				return nil, err
			}
		case iapCancellationDate:
			if purchase.CancellationDate, err = decodeDate(attr.value); err != nil {
				return nil, err
			}
		case iapIsInIntroOfferPeriod:
			if purchase.IsInIntroOfferPeriod, err = decodeInteger(attr.value); err != nil {
				return nil, err
			}
		default:
			recordUnknown(purchase.UnknownAttributes, attr)
		}
	}
	return purchase, nil
}

func recordUnknown(into map[int64][][]byte, attr receiptAttribute) {
	into[attr.kind] = append(into[attr.kind], bytes.Clone(attr.value))
}

func parseAttributeSet(b []byte) ([]receiptAttribute, error) {
	node, err := der.Parse(b)
	if err != nil {
		return nil, wrapError(ReasonInvalidReceiptFormat, err, "receipt payload is not valid ASN.1")
	}
	if der.IsOctetString(node) {
		// Xcode receipts double-wrap the payload in an extra OCTET STRING.
		node, err = der.Parse(der.OctetValue(node))
		if err != nil {
			return nil, wrapError(ReasonInvalidReceiptFormat, err,
				"receipt payload double-wrap is not valid ASN.1")
		}
	}
	if node.Tag != der.TagSet {
		return nil, newError(ReasonInvalidReceiptFormat, "receipt payload is not an ASN.1 SET")
	}
	attributes := make([]receiptAttribute, 0, len(node.Children))
	for _, child := range node.Children {
		kindNode := der.Child(child, 0)
		valueNode := der.Child(child, 2)
		if child.Tag != der.TagSequence || len(child.Children) < 3 ||
			kindNode.Tag != der.TagInteger || !der.IsOctetString(valueNode) {
			return nil, newError(ReasonInvalidReceiptFormat, "malformed receipt attribute")
		}
		kind, err := attributeType(kindNode)
		if err != nil {
			return nil, err
		}
		attributes = append(attributes, receiptAttribute{kind: kind, value: der.OctetValue(valueNode)})
	}
	return attributes, nil
}

func attributeType(node *der.Node) (int64, error) {
	kind, err := integerValue(node)
	if err != nil {
		return 0, err
	}
	if kind > maxAttributeType {
		return 0, newError(ReasonInvalidReceiptFormat,
			"receipt attribute type exceeds the 32-bit signed range")
	}
	return kind, nil
}

// integerValue decodes a non-negative receipt integer.
//
// Negative values never occur in genuine receipts and are rejected rather
// than sign-extended; the eight-octet cap keeps the value inside int64
// (with the high bit already excluded by the negative check) so no port
// has to decide what a bignum attribute means.
func integerValue(node *der.Node) (int64, error) {
	if len(node.Contents) > 8 {
		return 0, newError(ReasonInvalidReceiptFormat, "receipt integer out of range")
	}
	if len(node.Contents) > 0 && node.Contents[0] >= 0x80 {
		return 0, newError(ReasonInvalidReceiptFormat, "negative receipt integer")
	}
	value := int64(0)
	for _, b := range node.Contents {
		value = value<<8 | int64(b)
	}
	return value, nil
}

func decodeValue(b []byte) (*der.Node, error) {
	node, err := der.Parse(b)
	if err != nil {
		return nil, wrapError(ReasonInvalidReceiptFormat, err, "attribute value is not valid ASN.1")
	}
	return node, nil
}

func decodeString(b []byte) (string, error) {
	node, err := decodeValue(b)
	if err != nil {
		return "", err
	}
	if node.Tag != der.TagUTF8String && node.Tag != der.TagIA5String {
		return "", newError(ReasonInvalidReceiptFormat, "attribute value is not an ASN.1 string")
	}
	return string(node.Contents), nil
}

func decodeInteger(b []byte) (*int64, error) {
	node, err := decodeValue(b)
	if err != nil {
		return nil, err
	}
	if node.Tag != der.TagInteger {
		return nil, newError(ReasonInvalidReceiptFormat, "attribute value is not an ASN.1 integer")
	}
	value, err := integerValue(node)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

// decodeDate reads an RFC 3339 date from an IA5String. An empty string
// means "absent" — genuine receipts do that for a missing expiration.
//
// The timezone designator is mandatory. The creation date is the instant
// certificate validity is judged at, so a naive date would make the same
// receipt verify on one host and fail on another.
func decodeDate(b []byte) (*time.Time, error) {
	text, err := decodeString(b)
	if err != nil {
		return nil, err
	}
	if text == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, text)
	if err != nil {
		return nil, newError(ReasonInvalidReceiptFormat, "unparseable receipt date")
	}
	utc := parsed.UTC()
	return &utc, nil
}
