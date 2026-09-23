package applereceipt

// Test-only hooks for the external conformance_test package, which runs the
// decodeBase64 groups of fixtures/cases.json against the two base64
// decoders directly rather than through a verifier.

// DecodeReceiptDataForTest is the receipt-data decoder every base64 entry
// point uses, the size cap included.
func DecodeReceiptDataForTest(text string) ([]byte, error) { return receiptFromBase64(text) }

// DecodeX5CEntryForTest is the decoder parseX5CCertificate hands an x5c
// entry to, with its refusal reported as parseX5CCertificate reports it.
func DecodeX5CEntryForTest(text string) ([]byte, error) {
	der := decodeBase64(text)
	if der == nil {
		return nil, newError(ReasonInvalidCertificate, "x5c entry is not canonical standard base64")
	}
	return der, nil
}
