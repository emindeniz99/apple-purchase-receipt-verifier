package applereceipt_test

import (
	"bytes"
	"encoding/base64"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// The CMS certificate bag is the one region of a receipt the SignerInfo
// signature does not cover. Two different kinds of "bad" entry live
// there, and they get different verdicts (owner, 2026-09-27, matching
// the shared conformance cases):
//
//   - An entry that genuinely fails to parse as a certificate (garbage,
//     a truncated copy, the wrong ASN.1 shape) is exactly the kind of
//     stranger no pinned root ever vouches for. Unless its raw bytes name
//     the SignerInfo's own signer, it is simply excluded from the
//     top-down walk (Q16), the same as a certificate that parses fine but
//     names nobody real, never fatal on its own.
//   - An entry that DOES parse, but whose signature BIT STRING is not
//     canonically encoded, is fatal wherever it sits, signer or stranger:
//     crypto/x509 parses it anyway, silently reinterpreting the
//     signature bytes as something other than what was actually signed
//     (see certificateSignatureIsCanonicallyEncoded in receipt.go), which
//     is exactly the platform-parser leniency this library refuses to
//     trust.
func TestUnparseableStrangerCertificateIsTolerated(t *testing.T) {
	pki := newReceiptPKI(t)
	junk := derSequence(derInt(42), derInt(43)) // a SEQUENCE, not a Certificate
	receipt := buildCMS(t, cmsSpec{
		content:         receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
		signer:          pki.leaf,
		certificates:    [][]byte{pki.leaf.der, pki.intermediate.der, junk},
		withSignedAttrs: true,
	})
	if _, err := verifierFor(t, pki.anchors()).VerifyReceipt(applereceiptBase64(receipt)); err != nil {
		t.Fatalf("a genuinely undecodable stranger, not named by any SignerInfo, "+
			"must not be blamed on the receipt: %v", err)
	}
}

// signatureBitStringOffset locates the "unused bits" octet of an RSA-2048
// certificate's outer signatureValue BIT STRING: Certificate ::= SEQUENCE
// { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING } always
// puts it last, so its 257-byte content (1 unused-bits octet + 256
// signature bytes) ends exactly at len(der), long-form length-encoded as
// 03 82 01 01.
func signatureBitStringOffset(t *testing.T, der []byte) int {
	t.Helper()
	header := []byte{0x03, 0x82, 0x01, 0x01}
	at := len(der) - len(header) - 257
	if at < 0 || !bytes.Equal(der[at:at+len(header)], header) {
		t.Fatalf("could not locate a 2048-bit RSA signature BIT STRING at the expected offset")
	}
	return at + len(header)
}

// withNonCanonicalSignature returns a copy of an RSA-2048 certificate's
// DER whose signature BIT STRING declares one unused bit where zero is
// canonical, the fault the shared conformance cases pin
// (fault: stranger-certificate-signature-unaligned, x5c-leaf-signature-unaligned).
func withNonCanonicalSignature(t *testing.T, der []byte) []byte {
	t.Helper()
	at := signatureBitStringOffset(t, der)
	if der[at] != 0x00 {
		t.Fatalf("signature BIT STRING at %d already declares %d unused bits", at, der[at])
	}
	mutated := bytes.Clone(der)
	mutated[at] = 0x01
	// crypto/x509 additionally requires the padding bit it is about to
	// discard to already be zero-valued (DER's own rule for unused bits),
	// and refuses to parse the certificate at all otherwise: a random
	// RSA signature has that bit set about half the time. Clearing it
	// keeps this deterministic: crypto/x509 accepts the certificate
	// (silently right-aligning every byte of cert.Signature by one bit,
	// same as a genuine 1-unused-bit encoding would), so it is this
	// package's own canonicality check, not crypto/x509's parse, that is
	// under test.
	mutated[len(mutated)-1] &^= 0x01
	return mutated
}

func TestNonCanonicalCertificateSignatureIsFatalAtEveryPosition(t *testing.T) {
	pki := newReceiptPKI(t)
	nonCanonicalIntermediate := withNonCanonicalSignature(t, pki.intermediate.der)
	nonCanonicalLeaf := withNonCanonicalSignature(t, pki.leaf.der)
	positions := map[string][][]byte{
		"as a stranger, first": {nonCanonicalIntermediate, pki.leaf.der, pki.intermediate.der},
		"as a stranger, last":  {pki.leaf.der, pki.intermediate.der, nonCanonicalIntermediate},
		// The same issuer and serial as the genuine leaf (only the
		// trailing signature bytes, well after the TBS, are touched), so
		// it is found by identity as the signer, and must still be
		// fatal, not merely dropped as a stranger.
		"as the signer's own copy, replacing it": {nonCanonicalLeaf, pki.intermediate.der},
	}
	for name, certificates := range positions {
		t.Run(name, func(t *testing.T) {
			receipt := buildCMS(t, cmsSpec{
				content: receiptPayload(standardReceiptAttributes(
					"com.example.app", "ProductionSandbox", time.Now())...),
				signer:          pki.leaf,
				certificates:    certificates,
				withSignedAttrs: true,
			})
			_, err := verifierFor(t, pki.anchors()).VerifyReceipt(applereceiptBase64(receipt))
			requireReason(t, err, applereceipt.ReasonMalformed)
		})
	}
}

// The same thing on a genuine, Apple-signed receipt, and its converse: a
// corrupted NON-essential embedded certificate (this fixture carries a
// redundant copy of the root, which is not on the trust path since the
// path is built from the pinned AppleRoots(), not from the bag) does not
// stop the receipt verifying. Corrupting the actual signer still does.
func TestCorruptedCertificateInGenuineReceipt(t *testing.T) {
	const nonEssentialOffset = 4044
	receipt := genuineSandboxG5(t)
	verifier := verifierFor(t, applereceipt.AppleRoots())
	if _, err := verifier.VerifyReceipt(applereceiptBase64(receipt)); err != nil {
		t.Fatalf("the genuine fixture must verify first: %v", err)
	}
	t.Run("a non-essential embedded certificate", func(t *testing.T) {
		mutant := append([]byte(nil), receipt...)
		mutant[nonEssentialOffset] ^= 0xff
		if _, err := verifier.VerifyReceipt(applereceiptBase64(mutant)); err != nil {
			t.Fatalf("corrupting a certificate the trust path never uses must not "+
				"stop a genuinely signed receipt from verifying: %v", err)
		}
	})
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
// matter, and the shape of the junk must not matter either: none of
// these ever names the real signer, so none of them is ever blamed on
// the receipt. Q16 tolerance holds regardless of position or shape.
func TestUnparseableStrangerCertificateIsToleratedAtEveryPosition(t *testing.T) {
	pki := newReceiptPKI(t)
	// A truncated copy of a real certificate is deliberately not one of
	// these shapes: cutting DER mid-value can corrupt the outer CMS SET's
	// own boundary, which is a different failure (MALFORMED, from the
	// structural parse) than an embedded certificate merely failing to
	// decode on its own.
	junk := map[string][]byte{
		"a SEQUENCE that is not a Certificate": derSequence(derInt(42), derInt(43)),
		"an empty SEQUENCE":                    derSequence(),
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
				if _, err := verifierFor(t, pki.anchors()).VerifyReceipt(applereceiptBase64(receipt)); err != nil {
					t.Fatalf("an undecodable stranger, not named by the SignerInfo, must not be fatal: %v", err)
				}
			})
		}
	}
}

// Rejecting an undecodable entry must not move the cheap bound that
// protects it: the certificate COUNT is still checked before anything in
// the bag is decoded, so a bag stuffed with junk costs a count comparison
// and reports MALFORMED, not a thousand failed parses.
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
	_, err := verifierFor(t, pki.anchors()).VerifyReceipt(applereceiptBase64(receipt))
	requireReason(t, err, applereceipt.ReasonMalformed)
}

// A receipt naming a signer it does not carry is a defect of the RECEIPT,
// and stays one when the bag also holds an unrelated entry that will not
// parse. Blaming the malformed stranger for the absent signer would be a
// guess: the two are separate defects, and the only thing that connects an
// unreadable entry to the SignerInfo is the identity the entry itself
// carries. Node (findSignerCertIndex) and Swift (unreadableNodes) read that
// identity out of the raw DER; this port does too.
func TestAnAbsentSignerIsNotBlamedOnAMalformedStranger(t *testing.T) {
	pki := newReceiptPKI(t)
	junk := derSequence(derInt(42), derInt(43)) // a SEQUENCE, not a Certificate
	receipt := buildCMS(t, cmsSpec{
		content: receiptPayload(standardReceiptAttributes(
			"com.example.app", "ProductionSandbox", time.Now())...),
		signer: pki.leaf,
		// An identity nothing in the bag has: the leaf is not embedded and
		// the serial is not its own either.
		signerSerial:    big.NewInt(0x5eed),
		certificates:    [][]byte{pki.intermediate.der, junk},
		withSignedAttrs: true,
	})
	_, err := verifierFor(t, pki.anchors()).VerifyReceipt(applereceiptBase64(receipt))
	requireReason(t, err, applereceipt.ReasonMalformed)
}

// The other side of the same rule: when the unreadable entry IS the one the
// SignerInfo names, the verdict is about the certificate, exactly as it is
// for an unreadable x5c entry on the JWS path. The entry below is not a
// certificate (everything after the identity is missing), but the
// identity itself is intact, which is all that matching it to the
// SignerInfo needs.
func TestAMalformedSignerIsACertificateDefect(t *testing.T) {
	pki := newReceiptPKI(t)
	namedButUnreadable := derSequence(
		derSequence(
			derContext0(derInt(2)),
			derInteger(pki.leaf.cert.SerialNumber),
			derSequence(derOID(oidSHA256), derNull()),
			pki.leaf.cert.RawIssuer,
		),
	)
	receipt := buildCMS(t, cmsSpec{
		content: receiptPayload(standardReceiptAttributes(
			"com.example.app", "ProductionSandbox", time.Now())...),
		signer:          pki.leaf,
		certificates:    [][]byte{namedButUnreadable, pki.intermediate.der},
		withSignedAttrs: true,
	})
	_, err := verifierFor(t, pki.anchors()).VerifyReceipt(applereceiptBase64(receipt))
	requireReason(t, err, applereceipt.ReasonInvalidCertificate)
}
