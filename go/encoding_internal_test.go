package applereceipt

import (
	"encoding/base64"
	"testing"
)

// The spellings decodeBase64 must accept and refuse are the decodeBase64
// groups of fixtures/cases.json, which conformance_test.go runs against
// both decoders through export_test.go. What stays here is the one thing
// a shared vector cannot say: why the precheck in front of the standard
// decoder exists.

// Why isCanonicalBase64 exists: the standard decoder alone skips CR and LF
// and decodes the empty string, both of which Apple refuses.
func TestStdEncodingAloneIsNotTheRule(t *testing.T) {
	for _, text := range []string{"", "QUJD\n", "QU\r\nJD"} {
		if _, err := base64.StdEncoding.DecodeString(text); err != nil {
			t.Errorf("StdEncoding refused %q (%v); the precheck may no longer be needed", text, err)
		}
	}
}
