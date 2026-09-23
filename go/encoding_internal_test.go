package applereceipt

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// decodeBase64 must answer what Apple's verifyReceipt answered on
// 2026-09-23 for the same spellings of genuine receipts
// (docs/evidence/2026-09-23-verifyreceipt-base64.md). A spelling Apple
// decodes must decode here to the same bytes; a spelling Apple answers
// 21002 must be refused here, or a receipt verifies in Go that Apple itself
// refuses. The conformance cases pin the rule on a real receipt; this pins
// each shape on its own, including the ones base64.StdEncoding alone
// would have accepted.

func TestDecodeBase64AcceptsCanonicalSpellingsAndTrailingBits(t *testing.T) {
	for text, want := range map[string]string{
		"QUJD": "ABC",
		"QUI=": "AB",
		"QQ==": "A",
		"+/8=": "\xfb\xff",
		// Unused low bits set in the last data character: Apple accepts
		// them, and StdEncoding.Strict() would not.
		"QR==": "A",
		"Qf==": "A",
		"QUJ=": "AB",
	} {
		if got := decodeBase64(text); !bytes.Equal(got, []byte(want)) {
			t.Errorf("decodeBase64(%q) = %q, want %q", text, got, want)
		}
	}
}

func TestDecodeBase64RefusesEverySpellingAppleRefuses(t *testing.T) {
	for _, text := range []string{
		"",
		"QQ", "QUI", // padding omitted
		"QQ=",             // under-padded
		"QQ===", "QQ====", // extra padding
		"QUJD=", "QUJD==", "QUJD====", "==", // padding after a full group
		"Q===", "QUJDR", // impossible length
		"QQ==QUJD", "QQ==!!!!", // data or junk after the padding
		"QU!D",                             // junk inside
		"QUJD\n", "QUJD\r\n", "QUJD\nQUJD", // line feeds: StdEncoding alone skips them
		"QUJ\r\nD\r\n",
		" QUJD", "QU JD", "QU\tJD", "  QUJD  ", // other whitespace
		"-_8=", "-_8", "+_8=", // base64url, unpadded, mixed
		"QUJ\xc3\xa9", // outside ASCII
	} {
		if got := decodeBase64(text); got != nil {
			t.Errorf("decodeBase64(%q) = %q, want nil", text, got)
		}
	}
}

// Why isCanonicalBase64 exists: the standard decoder alone skips CR and LF
// and decodes the empty string, both of which Apple refuses.
func TestStdEncodingAloneIsNotTheRule(t *testing.T) {
	for _, text := range []string{"", "QUJD\n", "QU\r\nJD"} {
		if _, err := base64.StdEncoding.DecodeString(text); err != nil {
			t.Errorf("StdEncoding refused %q (%v); the precheck may no longer be needed", text, err)
		}
	}
}
