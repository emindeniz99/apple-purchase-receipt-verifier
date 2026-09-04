package applereceipt_test

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// The CMS certificate bag is the one region of a receipt the SignerInfo
// signature does not cover, so it is exactly where an attacker can
// rewrite a genuine receipt for free. A verifier that cannot parse an
// entry there must reject the receipt, not skip past it: skipping means
// answering "verified" about bytes the library could not read, and it is
// what the other four ports refuse to do.
//
//	Node   cms.certificates.map((raw) => new X509Certificate(raw)) inside
//	       the try that becomes INVALID_RECEIPT_FORMAT
//	Python x509.load_der_x509_certificate(raw) inside _parse_cms's broad
//	       except -> INVALID_RECEIPT_FORMAT
//	Swift  try Certificate(derEncoded: der) in the CMS parser
//	Java   converter.getCertificate(holder) for every holder, throwing
//	       GeneralSecurityException
func TestUnparseableEmbeddedCertificateIsFatal(t *testing.T) {
	pki := newReceiptPKI(t)
	junk := derSequence(derInt(42), derInt(43)) // a SEQUENCE, not a Certificate
	receipt := buildCMS(t, cmsSpec{
		content:         receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
		signer:          pki.leaf,
		certificates:    [][]byte{pki.leaf.der, pki.intermediate.der, junk},
		withSignedAttrs: true,
	})
	if _, err := applereceipt.VerifyReceiptCore(receipt, pki.anchors()); err == nil {
		t.Fatal("a receipt carrying an undecodable certificate was verified; " +
			"the bag is unsigned, so anything in it that cannot be parsed must be fatal")
	} else {
		requireReason(t, err, applereceipt.ReasonInvalidReceiptFormat)
	}

	// Control: the same receipt without the junk entry verifies, so the
	// rejection above is about the junk and nothing else.
	clean := buildCMS(t, cmsSpec{
		content:         receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
		signer:          pki.leaf,
		certificates:    pki.embedded(),
		withSignedAttrs: true,
	})
	if _, err := applereceipt.VerifyReceiptCore(clean, pki.anchors()); err != nil {
		t.Fatalf("control receipt did not verify: %v", err)
	}
}

// The same thing on a genuine, Apple-signed receipt. Byte 4044 of this
// fixture is inside its third embedded certificate; flipping it leaves
// the signed payload untouched, so a verifier that skips the entry
// happily returns a fully populated AppReceipt. Node rejects this exact
// mutant with INVALID_RECEIPT_FORMAT.
func TestCorruptedCertificateInGenuineReceiptIsFatal(t *testing.T) {
	const corruptOffset = 4044
	receipt := genuineSandboxG5(t)
	if _, err := applereceipt.VerifyReceiptCore(receipt, applereceipt.AppleReceiptRoots()); err != nil {
		t.Fatalf("the genuine fixture must verify first: %v", err)
	}
	mutant := append([]byte(nil), receipt...)
	mutant[corruptOffset] ^= 0xff
	result, err := applereceipt.VerifyReceiptCore(mutant, applereceipt.AppleReceiptRoots())
	if err == nil {
		t.Fatalf("a receipt with a corrupted embedded certificate verified as %q; "+
			"every other port rejects it", result.BundleID)
	}
	requireReason(t, err, applereceipt.ReasonInvalidReceiptFormat)
}

func genuineSandboxG5(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join("..", "fixtures", "public-receipts", "receipt-sandbox-g5.b64")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(raw)), ""))
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// The bag is unsigned wherever the entry sits, so position must not
// matter, and the shape of the junk must not matter either: anything
// x509 cannot decode is fatal.
func TestUnparseableCertificateIsFatalAtEveryPosition(t *testing.T) {
	pki := newReceiptPKI(t)
	junk := map[string][]byte{
		"a SEQUENCE that is not a Certificate": derSequence(derInt(42), derInt(43)),
		"an empty SEQUENCE":                    derSequence(),
		"a truncated copy of the real leaf":    derSequence(pki.leaf.der[2 : len(pki.leaf.der)/2]),
		"an OCTET STRING of random bytes":      derOctetString([]byte("not a certificate at all")),
	}
	positions := map[string]func(entry []byte) [][]byte{
		"first":  func(e []byte) [][]byte { return [][]byte{e, pki.leaf.der, pki.intermediate.der} },
		"middle": func(e []byte) [][]byte { return [][]byte{pki.leaf.der, e, pki.intermediate.der} },
		"last":   func(e []byte) [][]byte { return [][]byte{pki.leaf.der, pki.intermediate.der, e} },
	}
	for shape, entry := range junk {
		for position, arrange := range positions {
			t.Run(shape+"/"+position, func(t *testing.T) {
				receipt := buildCMS(t, cmsSpec{
					content: receiptPayload(standardReceiptAttributes(
						"com.example.app", "ProductionSandbox", time.Now())...),
					signer:          pki.leaf,
					certificates:    arrange(entry),
					withSignedAttrs: true,
				})
				_, err := applereceipt.VerifyReceiptCore(receipt, pki.anchors())
				if err == nil {
					t.Fatal("an undecodable certificate in the bag was tolerated")
				}
				requireReason(t, err, applereceipt.ReasonInvalidReceiptFormat)
			})
		}
	}
}

// Rejecting an undecodable entry must not move the cheap bound that
// protects it: the certificate COUNT is still checked before anything in
// the bag is decoded, so a bag stuffed with junk costs a count comparison
// and reports INVALID_CHAIN, not a thousand failed parses.
func TestCertificateCountIsStillCheckedBeforeDecoding(t *testing.T) {
	pki := newReceiptPKI(t)
	bag := make([][]byte, 0, 64)
	for i := 0; i < 64; i++ {
		bag = append(bag, derSequence(derInt(int64(i))))
	}
	receipt := buildCMS(t, cmsSpec{
		content: receiptPayload(standardReceiptAttributes(
			"com.example.app", "ProductionSandbox", time.Now())...),
		signer:          pki.leaf,
		certificates:    bag,
		withSignedAttrs: true,
	})
	_, err := applereceipt.VerifyReceiptCore(receipt, pki.anchors())
	requireReason(t, err, applereceipt.ReasonInvalidChain)
}
