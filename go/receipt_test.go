package applereceipt_test

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

func receiptVerifier(t *testing.T, pki receiptPKI, bundleID string) *applereceipt.ReceiptVerifier {
	t.Helper()
	verifier, err := applereceipt.NewReceiptVerifier(applereceipt.ReceiptVerifierOptions{
		TrustedRoots: pki.anchors(),
		BundleID:     bundleID,
	})
	if err != nil {
		t.Fatalf("NewReceiptVerifier: %v", err)
	}
	return verifier
}

// requireReason asserts that err is a *VerificationError with the given
// reason. An error of any other type is reported as such rather than
// being coerced into a reason — that is the whole point of the
// containment rule.
func requireReason(t *testing.T, err error, want applereceipt.Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got no error", want)
	}
	var verr *applereceipt.VerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("expected a *VerificationError with reason %s, got %T: %v", want, err, err)
	}
	if verr.Reason != want {
		t.Fatalf("reason: got %s, want %s (%v)", verr.Reason, want, err)
	}
}

func TestSynthesizedReceiptVerifies(t *testing.T) {
	pki := newReceiptPKI(t)
	receipt, err := receiptVerifier(t, pki, "com.example.app").Verify(pki.receipt(t))
	if err != nil {
		t.Fatalf("a well-formed synthesized receipt must verify: %v", err)
	}
	if receipt.BundleID != "com.example.app" || receipt.AppVersion != "1.2.3" {
		t.Fatalf("decoded fields are wrong: %+v", receipt)
	}
}

func TestReceiptWithoutSignedAttributesVerifies(t *testing.T) {
	// Not every CMS SignerInfo carries signed attributes; when there are
	// none the signature covers the content directly.
	pki := newReceiptPKI(t)
	der := buildCMS(t, cmsSpec{
		content:      receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
		signer:       pki.leaf,
		certificates: pki.embedded(),
	})
	if _, err := receiptVerifier(t, pki, "com.example.app").Verify(der); err != nil {
		t.Fatalf("content-signed receipt must verify: %v", err)
	}
}

func TestReceiptHostileStructures(t *testing.T) {
	pki := newReceiptPKI(t)
	good := pki.receipt(t)
	verifier := receiptVerifier(t, pki, "com.example.app")

	tests := []struct {
		name  string
		input []byte
		want  applereceipt.Reason
	}{
		{
			// The whole reason der.Parse rejects a remainder: an
			// unverified tail must not ride along on a verified blob.
			name:  "trailing bytes after the CMS blob",
			input: append(bytes.Clone(good), 0x00, 0x01, 0x02),
			want:  applereceipt.ReasonInvalidReceiptFormat,
		},
		{
			name:  "truncated CMS blob",
			input: good[:len(good)/2],
			want:  applereceipt.ReasonInvalidReceiptFormat,
		},
		{
			name:  "empty input",
			input: []byte{},
			want:  applereceipt.ReasonInvalidReceiptFormat,
		},
		{
			name:  "nil input",
			input: nil,
			want:  applereceipt.ReasonInvalidReceiptFormat,
		},
		{
			name:  "not ASN.1 at all",
			input: []byte("this is not a receipt"),
			want:  applereceipt.ReasonInvalidReceiptFormat,
		},
		{
			name:  "a bare SEQUENCE that is not a ContentInfo",
			input: derSequence(derInt(1)),
			want:  applereceipt.ReasonInvalidReceiptFormat,
		},
		{
			name: "no encapsulated content",
			input: buildCMS(t, cmsSpec{
				content: receiptPayload(), signer: pki.leaf,
				certificates: pki.embedded(), omitContent: true,
			}),
			want: applereceipt.ReasonInvalidReceiptFormat,
		},
		{
			name: "no SignerInfo",
			input: buildCMS(t, cmsSpec{
				content: receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
				signer:  pki.leaf, certificates: pki.embedded(), omitSignerInfos: true,
			}),
			want: applereceipt.ReasonInvalidReceiptFormat,
		},
		{
			name: "signer certificate not embedded",
			input: buildCMS(t, cmsSpec{
				content: receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
				signer:  pki.leaf, certificates: pki.embedded(),
				signerSerial: big.NewInt(999999), withSignedAttrs: true,
			}),
			want: applereceipt.ReasonInvalidReceiptFormat,
		},
		{
			name: "unsupported digest algorithm",
			input: buildCMS(t, cmsSpec{
				content: receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
				signer:  pki.leaf, certificates: pki.embedded(),
				digestOID: oidSHA512, withSignedAttrs: true,
			}),
			want: applereceipt.ReasonInvalidReceiptFormat,
		},
		{
			name: "messageDigest attribute does not match the content",
			input: buildCMS(t, cmsSpec{
				content: receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
				signer:  pki.leaf, certificates: pki.embedded(),
				withSignedAttrs: true, corruptMessageDigest: true,
			}),
			want: applereceipt.ReasonInvalidSignature,
		},
		{
			name: "corrupted signature",
			input: buildCMS(t, cmsSpec{
				content: receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
				signer:  pki.leaf, certificates: pki.embedded(),
				withSignedAttrs: true, badSignature: true,
			}),
			want: applereceipt.ReasonInvalidSignature,
		},
		{
			name: "payload is not an ASN.1 SET",
			input: buildCMS(t, cmsSpec{
				content: derSequence(derInt(1)), signer: pki.leaf,
				certificates: pki.embedded(), withSignedAttrs: true,
			}),
			want: applereceipt.ReasonInvalidReceiptFormat,
		},
		{
			name: "attribute is not a SEQUENCE of three",
			input: buildCMS(t, cmsSpec{
				content: derSet(derSequence(derInt(1), derInt(1))), signer: pki.leaf,
				certificates: pki.embedded(), withSignedAttrs: true,
			}),
			want: applereceipt.ReasonInvalidReceiptFormat,
		},
		{
			name: "negative attribute type",
			input: buildCMS(t, cmsSpec{
				content: receiptPayload(receiptAttribute(big.NewInt(-1), derUTF8String("x"))),
				signer:  pki.leaf, certificates: pki.embedded(), withSignedAttrs: true,
			}),
			want: applereceipt.ReasonInvalidReceiptFormat,
		},
		{
			name: "attribute type at 2^31 is out of range",
			input: buildCMS(t, cmsSpec{
				content: receiptPayload(attr(1<<31, derUTF8String("x"))),
				signer:  pki.leaf, certificates: pki.embedded(), withSignedAttrs: true,
			}),
			want: applereceipt.ReasonInvalidReceiptFormat,
		},
		{
			name: "attribute type at 2^63 is out of range",
			input: buildCMS(t, cmsSpec{
				content: receiptPayload(receiptAttribute(
					new(big.Int).Lsh(big.NewInt(1), 63), derUTF8String("x"))),
				signer: pki.leaf, certificates: pki.embedded(), withSignedAttrs: true,
			}),
			want: applereceipt.ReasonInvalidReceiptFormat,
		},
		{
			name: "attribute value is not valid ASN.1",
			input: buildCMS(t, cmsSpec{
				content: receiptPayload(attr(2, []byte{0x30, 0xff, 0xff})),
				signer:  pki.leaf, certificates: pki.embedded(), withSignedAttrs: true,
			}),
			want: applereceipt.ReasonInvalidReceiptFormat,
		},
		{
			name: "bundle id attribute is an integer, not a string",
			input: buildCMS(t, cmsSpec{
				content: receiptPayload(attr(2, derInt(7))),
				signer:  pki.leaf, certificates: pki.embedded(), withSignedAttrs: true,
			}),
			want: applereceipt.ReasonInvalidReceiptFormat,
		},
		{
			name: "quantity attribute is a string, not an integer",
			input: buildCMS(t, cmsSpec{
				content: receiptPayload(
					attr(2, derUTF8String("com.example.app")),
					attr(17, receiptPayload(attr(1701, derUTF8String("one"))))),
				signer: pki.leaf, certificates: pki.embedded(), withSignedAttrs: true,
			}),
			want: applereceipt.ReasonInvalidReceiptFormat,
		},
		{
			name: "creation date has no timezone designator",
			input: buildCMS(t, cmsSpec{
				content: receiptPayload(
					attr(2, derUTF8String("com.example.app")),
					attr(12, derIA5String("2024-08-06T12:00:00"))),
				signer: pki.leaf, certificates: pki.embedded(), withSignedAttrs: true,
			}),
			want: applereceipt.ReasonInvalidReceiptFormat,
		},
		{
			name: "creation date is nonsense",
			input: buildCMS(t, cmsSpec{
				content: receiptPayload(
					attr(2, derUTF8String("com.example.app")),
					attr(12, derIA5String("not a date"))),
				signer: pki.leaf, certificates: pki.embedded(), withSignedAttrs: true,
			}),
			want: applereceipt.ReasonInvalidReceiptFormat,
		},
		{
			name: "creation date at an expanded year",
			input: buildCMS(t, cmsSpec{
				content: receiptPayload(
					attr(2, derUTF8String("com.example.app")),
					attr(12, derIA5String("+1000000000-01-01T00:00:00Z"))),
				signer: pki.leaf, certificates: pki.embedded(), withSignedAttrs: true,
			}),
			want: applereceipt.ReasonInvalidReceiptFormat,
		},
		{
			name: "web_order_line_item_id above the eight-octet cap",
			input: buildCMS(t, cmsSpec{
				content: receiptPayload(
					attr(2, derUTF8String("com.example.app")),
					attr(17, receiptPayload(attr(1711,
						derInteger(new(big.Int).Lsh(big.NewInt(1), 200)))))),
				signer: pki.leaf, certificates: pki.embedded(), withSignedAttrs: true,
			}),
			want: applereceipt.ReasonInvalidReceiptFormat,
		},
		{
			name: "deeply nested attribute value",
			input: buildCMS(t, cmsSpec{
				content: receiptPayload(attr(2, nestedSequences(64))),
				signer:  pki.leaf, certificates: pki.embedded(), withSignedAttrs: true,
			}),
			want: applereceipt.ReasonInvalidReceiptFormat,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			_, err := verifier.Verify(test.input)
			requireReason(t, err, test.want)
		})
	}
}

func nestedSequences(depth int) []byte {
	out := derInt(1)
	for i := 0; i < depth; i++ {
		out = derSequence(out)
	}
	return out
}

func TestReceiptSignerKeyMustBeRSA(t *testing.T) {
	// An EC signer would otherwise reach the signature check with an
	// algorithm identifier claiming RSA.
	root := issueCert(t, certSpec{commonName: "EC Root", isCA: true, rsa: true}, nil)
	leaf := issueCert(t, certSpec{
		commonName: "EC Signer", markerOIDs: []asn1.ObjectIdentifier{oidAppleLeaf},
	}, root)
	der := buildCMS(t, cmsSpec{
		content:      receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
		signer:       leaf,
		certificates: [][]byte{leaf.der},
	})
	_, err := applereceipt.VerifyReceiptCore(der, []*x509.Certificate{root.cert})
	requireReason(t, err, applereceipt.ReasonInvalidSignature)
}

func TestReceiptSignerMustCarryTheMarkerOID(t *testing.T) {
	root := issueCert(t, certSpec{commonName: "Root", isCA: true, rsa: true}, nil)
	leaf := issueCert(t, certSpec{commonName: "Unmarked Signer", rsa: true}, root)
	der := buildCMS(t, cmsSpec{
		content:      receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
		signer:       leaf,
		certificates: [][]byte{leaf.der},
		// signed attributes so the signature itself would pass
		withSignedAttrs: true,
	})
	_, err := applereceipt.VerifyReceiptCore(der, []*x509.Certificate{root.cert})
	requireReason(t, err, applereceipt.ReasonInvalidCertificatePurpose)
}

// The certificate bound is enforced BEFORE any certificate is decoded.
// The proof: certificate number three is unparseable garbage, and the
// answer is still INVALID_CHAIN rather than anything about a certificate.
func TestCertificateFloodIsRejectedBeforeDecoding(t *testing.T) {
	pki := newReceiptPKI(t)
	certificates := [][]byte{pki.leaf.der, pki.intermediate.der, derSequence(derInt(1))}
	for i := 0; i < 20; i++ {
		certificates = append(certificates, derSequence(derOctetString(bytes.Repeat([]byte{0xab}, 64))))
	}
	der := buildCMS(t, cmsSpec{
		content:         receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
		signer:          pki.leaf,
		certificates:    certificates,
		withSignedAttrs: true,
	})
	_, err := applereceipt.VerifyReceiptCore(der, pki.anchors())
	requireReason(t, err, applereceipt.ReasonInvalidChain)
}

// Exactly ten is examined, not rejected by the bound.
func TestExactlyTenEmbeddedCertificatesIsExamined(t *testing.T) {
	pki := newReceiptPKI(t)
	certificates := pki.embedded()
	for len(certificates) < 10 {
		filler := issueCert(t, certSpec{commonName: "Filler", rsa: false}, pki.root)
		certificates = append(certificates, filler.der)
	}
	der := buildCMS(t, cmsSpec{
		content:         receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
		signer:          pki.leaf,
		certificates:    certificates,
		withSignedAttrs: true,
	})
	if _, err := applereceipt.VerifyReceiptCore(der, pki.anchors()); err != nil {
		t.Fatalf("ten embedded certificates must be examined, not rejected: %v", err)
	}
}

func TestDeviceHash(t *testing.T) {
	pki := newReceiptPKI(t)
	guid := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	opaque := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	bundleIDBytes := derUTF8String("com.example.app")
	h := sha1.New()
	h.Write(guid)
	h.Write(opaque)
	h.Write(bundleIDBytes)

	withHash := pki.receipt(t,
		attr(0, derUTF8String("ProductionSandbox")),
		attr(2, derUTF8String("com.example.app")),
		attr(4, opaque),
		attr(5, h.Sum(nil)),
		attr(12, derIA5String(time.Now().UTC().Format(time.RFC3339))),
	)
	verifier := receiptVerifier(t, pki, "com.example.app")

	t.Run("matching guid", func(t *testing.T) {
		if _, err := verifier.VerifyWithDeviceGUID(withHash, guid); err != nil {
			t.Fatalf("the matching device guid must verify: %v", err)
		}
	})
	t.Run("wrong guid", func(t *testing.T) {
		_, err := verifier.VerifyWithDeviceGUID(withHash, []byte("wrong"))
		requireReason(t, err, applereceipt.ReasonDeviceHashMismatch)
	})
	t.Run("base64 form with the matching guid", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString(withHash)
		if _, err := verifier.VerifyBase64WithDeviceGUID(encoded, guid); err != nil {
			t.Fatalf("the base64 + guid path must exist and verify: %v", err)
		}
	})
	t.Run("receipt without attribute 5", func(t *testing.T) {
		noHash := pki.receipt(t,
			attr(2, derUTF8String("com.example.app")),
			attr(4, opaque),
		)
		_, err := verifier.VerifyWithDeviceGUID(noHash, guid)
		requireReason(t, err, applereceipt.ReasonDeviceHashMismatch)
	})
	t.Run("receipt without attribute 4", func(t *testing.T) {
		noOpaque := pki.receipt(t,
			attr(2, derUTF8String("com.example.app")),
			attr(5, h.Sum(nil)),
		)
		_, err := verifier.VerifyWithDeviceGUID(noOpaque, guid)
		requireReason(t, err, applereceipt.ReasonDeviceHashMismatch)
	})
	t.Run("no guid means no device check", func(t *testing.T) {
		if _, err := verifier.Verify(withHash); err != nil {
			t.Fatalf("the device check is optional: %v", err)
		}
	})
}

func TestBase64AndDERPathsAgree(t *testing.T) {
	pki := newReceiptPKI(t)
	der := pki.receipt(t)
	verifier := receiptVerifier(t, pki, "com.example.app")
	fromDER, err := verifier.Verify(der)
	if err != nil {
		t.Fatal(err)
	}
	fromBase64, err := verifier.VerifyBase64(base64.StdEncoding.EncodeToString(der))
	if err != nil {
		t.Fatal(err)
	}
	if fromDER.BundleID != fromBase64.BundleID || !fromDER.CreationDate.Equal(*fromBase64.CreationDate) {
		t.Fatal("the DER and base64 entry points must decode the same receipt identically")
	}
	// Base64 leniency parity with Java's MIME decoder and Node's Buffer:
	// PEM-style line breaks and whitespace are skipped, not rejected.
	wrapped := wrapLines(base64.StdEncoding.EncodeToString(der), 64)
	if _, err := verifier.VerifyBase64(wrapped); err != nil {
		t.Fatalf("line-wrapped base64 must decode, as it does in the other ports: %v", err)
	}
}

func wrapLines(text string, width int) string {
	var out strings.Builder
	for i := 0; i < len(text); i += width {
		end := i + width
		if end > len(text) {
			end = len(text)
		}
		out.WriteString(text[i:end])
		out.WriteString("\n")
	}
	return out.String()
}

func TestWrongBundleIDIsCheckedAfterTheSignature(t *testing.T) {
	pki := newReceiptPKI(t)
	_, err := receiptVerifier(t, pki, "com.other.app").Verify(pki.receipt(t))
	requireReason(t, err, applereceipt.ReasonWrongBundleID)
}

// VerifyReceiptCore is public precisely so the endpoint does not have to
// build a wildcard-bundle-id verifier to reach it (cross-port contract
// C4). This test is that contract in executable form.
func TestVerifyReceiptCoreSkipsTheBundleIDCheck(t *testing.T) {
	pki := newReceiptPKI(t)
	receipt, err := applereceipt.VerifyReceiptCore(pki.receipt(t), pki.anchors())
	if err != nil {
		t.Fatalf("VerifyReceiptCore must verify without a configured bundle id: %v", err)
	}
	if receipt.BundleID != "com.example.app" {
		t.Fatalf("bundle id: got %q", receipt.BundleID)
	}
}

func TestVerifyReceiptCoreRejectsAnEmptyAnchorSet(t *testing.T) {
	pki := newReceiptPKI(t)
	_, err := applereceipt.VerifyReceiptCore(pki.receipt(t), nil)
	if err == nil {
		t.Fatal("an empty anchor set must be refused")
	}
	var verr *applereceipt.VerificationError
	if errors.As(err, &verr) {
		t.Fatalf("misconfiguration must not be a verification verdict, got %s", verr.Reason)
	}
}

// The aliasing rule: byte fields on a result are copies, so a caller that
// reuses its receipt buffer cannot mutate an already-verified receipt.
func TestResultDoesNotAliasTheInput(t *testing.T) {
	pki := newReceiptPKI(t)
	input := pki.receipt(t)
	receipt, err := applereceipt.VerifyReceiptCore(input, pki.anchors())
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(receipt.OpaqueValue)
	beforeBundle := receipt.BundleID
	for i := range input {
		input[i] ^= 0xff
	}
	if !bytes.Equal(receipt.OpaqueValue, before) {
		t.Fatal("OpaqueValue aliases the caller's buffer")
	}
	if receipt.BundleID != beforeBundle {
		t.Fatal("BundleID aliases the caller's buffer")
	}
	if overlaps(receipt.OpaqueValue, input) || overlaps(receipt.BundleIDBytes, input) ||
		overlaps(receipt.SHA1Hash, input) {
		t.Fatal("a returned byte field shares backing memory with the input")
	}
}

func overlaps(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	return &a[0] == &b[0]
}

func TestOversizedReceiptIsRejectedBeforeParsing(t *testing.T) {
	pki := newReceiptPKI(t)
	verifier, err := applereceipt.NewReceiptVerifier(applereceipt.ReceiptVerifierOptions{
		TrustedRoots: pki.anchors(), BundleID: "com.example.app", MaxReceiptBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier.Verify(bytes.Repeat([]byte{0x30}, 2048))
	requireReason(t, err, applereceipt.ReasonInvalidReceiptFormat)
	if _, err := verifier.Verify(pki.receipt(t)); err == nil {
		t.Fatal("the default-sized synthesized receipt is larger than 1024 bytes; " +
			"this test would not be testing the bound")
	}
}

func TestUnknownAttributesArePreserved(t *testing.T) {
	pki := newReceiptPKI(t)
	der := pki.receipt(t,
		attr(2, derUTF8String("com.example.app")),
		attr(9999, []byte{1, 2, 3}),
		attr(9999, []byte{4, 5, 6}),
		attr(17, receiptPayload(
			attr(1702, derUTF8String("com.example.app.pro")),
			attr(8888, []byte{7}))),
	)
	receipt, err := receiptVerifier(t, pki, "com.example.app").Verify(der)
	if err != nil {
		t.Fatal(err)
	}
	values := receipt.UnknownAttributes[9999]
	if len(values) != 2 || !bytes.Equal(values[0], []byte{1, 2, 3}) || !bytes.Equal(values[1], []byte{4, 5, 6}) {
		t.Fatalf("duplicates must be preserved in encounter order, got %v", values)
	}
	if len(receipt.InAppPurchases) != 1 {
		t.Fatalf("expected one in-app purchase, got %d", len(receipt.InAppPurchases))
	}
	inner := receipt.InAppPurchases[0].UnknownAttributes[8888]
	if len(inner) != 1 || !bytes.Equal(inner[0], []byte{7}) {
		t.Fatalf("in-app purchases carry their own unknown attributes, got %v", inner)
	}
}

func TestEmptyDateStringMeansAbsent(t *testing.T) {
	pki := newReceiptPKI(t)
	der := pki.receipt(t,
		attr(2, derUTF8String("com.example.app")),
		attr(21, derIA5String("")),
	)
	receipt, err := receiptVerifier(t, pki, "com.example.app").Verify(der)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ExpirationDate != nil {
		t.Fatalf("an empty date string means absent, got %v", receipt.ExpirationDate)
	}
}

// The receipt path checks the chain BEFORE the marker OID — the opposite
// of the JWS path — so a receipt signed by a foreign chain reports
// INVALID_CHAIN and not INVALID_CERTIFICATE_PURPOSE (PLAN.md §2.2 step 3).
// The signer here has neither property, which is what makes the order
// observable.
func TestReceiptChainIsCheckedBeforeTheMarkerOID(t *testing.T) {
	foreign := issueCert(t, certSpec{commonName: "Foreign Root", isCA: true, rsa: true}, nil)
	unmarked := issueCert(t, certSpec{commonName: "Unmarked Foreign Signer", rsa: true}, foreign)
	pinned := newReceiptPKI(t)

	der := buildCMS(t, cmsSpec{
		content:         receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
		signer:          unmarked,
		certificates:    [][]byte{unmarked.der},
		withSignedAttrs: true,
	})
	_, err := applereceipt.VerifyReceiptCore(der, pinned.anchors())
	requireReason(t, err, applereceipt.ReasonInvalidChain)
}

// Nothing from the payload may be returned or acted on before the chain
// and the signature pass, even though the payload is parsed first to
// learn the creation date.
func TestNoPartialResultOnFailure(t *testing.T) {
	pki := newReceiptPKI(t)
	other := newReceiptPKI(t)
	receipt, err := applereceipt.VerifyReceiptCore(pki.receipt(t), other.anchors())
	if err == nil {
		t.Fatal("expected a failure")
	}
	if receipt != nil {
		t.Fatalf("a failed verification returned a receipt anyway: %+v", receipt)
	}
}
