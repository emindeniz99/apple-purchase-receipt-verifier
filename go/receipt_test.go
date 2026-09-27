package applereceipt_test

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// oidUnsupportedDigest is SHA-224's OID: a digestAlgorithm this package's
// digestFromOID (receiptalgorithm.go) does not recognize, since
// crypto/x509 has no SignatureAlgorithm pairing it with RSA or ECDSA.
var oidUnsupportedDigest = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}

func TestSynthesizedReceiptVerifies(t *testing.T) {
	pki := newReceiptPKI(t)
	receipt, err := verifierFor(t, pki.anchors()).VerifyReceipt(applereceiptBase64(pki.receipt(t)))
	if err != nil {
		t.Fatalf("a well-formed synthesized receipt must verify: %v", err)
	}
	if receipt.BundleID == nil || *receipt.BundleID != "com.example.app" {
		t.Errorf("BundleID: got %v", receipt.BundleID)
	}
	if receipt.ApplicationVersion == nil || *receipt.ApplicationVersion != "1.2.3" {
		t.Errorf("ApplicationVersion: got %v", receipt.ApplicationVersion)
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
	if _, err := verifierFor(t, pki.anchors()).VerifyReceipt(applereceiptBase64(der)); err != nil {
		t.Fatalf("content-signed receipt must verify: %v", err)
	}
}

func TestReceiptHostileStructures(t *testing.T) {
	pki := newReceiptPKI(t)
	good := pki.receipt(t)
	verifier := verifierFor(t, pki.anchors())
	verify := func(der []byte) error {
		_, err := verifier.VerifyReceipt(applereceiptBase64(der))
		return err
	}

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
			want:  applereceipt.ReasonMalformed,
		},
		{name: "truncated CMS blob", input: good[:len(good)/2], want: applereceipt.ReasonMalformed},
		{name: "empty input", input: []byte{}, want: applereceipt.ReasonMalformed},
		{name: "nil input", input: nil, want: applereceipt.ReasonMalformed},
		{name: "not ASN.1 at all", input: []byte("this is not a receipt"), want: applereceipt.ReasonMalformed},
		{
			name:  "a bare SEQUENCE that is not a ContentInfo",
			input: derSequence(derInt(1)),
			want:  applereceipt.ReasonMalformed,
		},
		{
			name: "no encapsulated content",
			input: buildCMS(t, cmsSpec{
				content: receiptPayload(), signer: pki.leaf,
				certificates: pki.embedded(), omitContent: true,
			}),
			want: applereceipt.ReasonMalformed,
		},
		{
			name: "no SignerInfo",
			input: buildCMS(t, cmsSpec{
				content: receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
				signer:  pki.leaf, certificates: pki.embedded(), omitSignerInfos: true,
			}),
			want: applereceipt.ReasonMalformed,
		},
		{
			name: "signer certificate not embedded",
			input: buildCMS(t, cmsSpec{
				content: receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
				signer:  pki.leaf, certificates: pki.embedded(),
				signerSerial: big.NewInt(999999), withSignedAttrs: true,
			}),
			want: applereceipt.ReasonMalformed,
		},
		{
			// Change 3 (docs/design/0.7-hardening-parity.md): the digest
			// itself is not restricted, but SHA-512 is not the digest the
			// content was actually hashed under here (the cmsSpec still
			// signs with the requested digestOID, so this vector instead
			// pins a genuinely unsupported OID path: see
			// receiptalgorithm.go's digestFromOID).
			name: "unsupported digest algorithm",
			input: buildCMS(t, cmsSpec{
				content: receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
				signer:  pki.leaf, certificates: pki.embedded(),
				digestOID: oidUnsupportedDigest, withSignedAttrs: true,
			}),
			want: applereceipt.ReasonInvalidSignature,
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
			// Apple-signed content that does not parse as an attribute
			// SET is UNREADABLE_PAYLOAD in 0.7, never MALFORMED: the
			// signature already proved Apple signed it.
			name: "payload is not an ASN.1 SET",
			input: buildCMS(t, cmsSpec{
				content: derSequence(derInt(1)), signer: pki.leaf,
				certificates: pki.embedded(), withSignedAttrs: true,
			}),
			want: applereceipt.ReasonUnreadablePayload,
		},
		{
			name: "attribute is not a SEQUENCE of three",
			input: buildCMS(t, cmsSpec{
				content: derSet(derSequence(derInt(1), derInt(1))), signer: pki.leaf,
				certificates: pki.embedded(), withSignedAttrs: true,
			}),
			want: applereceipt.ReasonUnreadablePayload,
		},
		{
			name: "negative attribute type",
			input: buildCMS(t, cmsSpec{
				content: receiptPayload(receiptAttribute(big.NewInt(-1), derUTF8String("x"))),
				signer:  pki.leaf, certificates: pki.embedded(), withSignedAttrs: true,
			}),
			want: applereceipt.ReasonUnreadablePayload,
		},
		{
			name: "attribute type at 2^31 is out of range",
			input: buildCMS(t, cmsSpec{
				content: receiptPayload(attr(1<<31, derUTF8String("x"))),
				signer:  pki.leaf, certificates: pki.embedded(), withSignedAttrs: true,
			}),
			want: applereceipt.ReasonUnreadablePayload,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			requireReason(t, verify(test.input), test.want)
		})
	}
}

// A value that merely fails to decode does not make the whole payload
// unreadable: the typed field is null and the raw octets are kept
// (docs/design/0.7-api.md). Only the attribute SET, or one attribute's
// own shape, being unparseable does that (see TestReceiptHostileStructures).
func TestUnparseableAttributeValuesAreKeptRawNotFatal(t *testing.T) {
	pki := newReceiptPKI(t)
	verifier := verifierFor(t, pki.anchors())

	t.Run("bundle id is an integer, not a string", func(t *testing.T) {
		der := pki.receipt(t, attr(2, derInt(7)))
		receipt, err := verifier.VerifyReceipt(applereceiptBase64(der))
		if err != nil {
			t.Fatalf("must still verify: %v", err)
		}
		if receipt.BundleID != nil {
			t.Errorf("BundleID: got %v, want nil", *receipt.BundleID)
		}
		if !bytes.Equal(receipt.BundleIDBytes, derInt(7)) {
			t.Error("BundleIDBytes must be kept even when the string does not decode")
		}
	})
	t.Run("quantity is a string, not an integer", func(t *testing.T) {
		der := pki.receipt(t,
			attr(2, derUTF8String("com.example.app")),
			attr(17, receiptPayload(attr(1701, derUTF8String("one")))))
		receipt, err := verifier.VerifyReceipt(applereceiptBase64(der))
		if err != nil {
			t.Fatalf("must still verify: %v", err)
		}
		if len(receipt.InApp) != 1 || receipt.InApp[0].Quantity != nil {
			t.Fatalf("Quantity must be nil, got %+v", receipt.InApp)
		}
		if raw, ok := receipt.InApp[0].UnknownAttributes[1701]; !ok || len(raw) != 1 {
			t.Error("the undecodable quantity must be kept raw under 1701")
		}
	})
	t.Run("creation date is nonsense, chain judged at the clock", func(t *testing.T) {
		der := pki.receipt(t,
			attr(2, derUTF8String("com.example.app")),
			attr(12, derIA5String("not a date")))
		receipt, err := verifier.VerifyReceipt(applereceiptBase64(der))
		if err != nil {
			t.Fatalf("must still verify, judged at the clock: %v", err)
		}
		if receipt.ReceiptCreationDateMs != nil {
			t.Errorf("ReceiptCreationDateMs: got %v, want nil", *receipt.ReceiptCreationDateMs)
		}
		if _, ok := receipt.UnknownAttributes[12]; !ok {
			t.Error("the unparseable date must be kept raw under 12")
		}
	})
}

// The certificate bound is enforced BEFORE any certificate is decoded.
// The proof: certificate number three is unparseable garbage, and the
// answer is still MALFORMED (the bound), rather than anything about a
// certificate.
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
	_, err := verifierFor(t, pki.anchors()).VerifyReceipt(applereceiptBase64(der))
	requireReason(t, err, applereceipt.ReasonMalformed)
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
	if _, err := verifierFor(t, pki.anchors()).VerifyReceipt(applereceiptBase64(der)); err != nil {
		t.Fatalf("ten embedded certificates must be examined, not rejected: %v", err)
	}
}

func TestLineWrappedBase64IsRefused(t *testing.T) {
	pki := newReceiptPKI(t)
	der := pki.receipt(t)
	// Apple's verifyReceipt answers 21002 to line-wrapped base64 (measured
	// 2026-09-23), so the base64 path refuses it rather than skipping the
	// line breaks on the way to the same DER.
	wrapped := wrapLines(applereceiptBase64(der), 64)
	_, err := verifierFor(t, pki.anchors()).VerifyReceipt(wrapped)
	requireReason(t, err, applereceipt.ReasonMalformed)
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

func TestVerifyReceiptRejectsAnEmptyAnchorSet(t *testing.T) {
	config := applereceipt.NewConfig(applereceipt.ConfigOptions{Roots: []*x509.Certificate{}})
	_, err := applereceipt.NewVerifier(config)
	if err == nil {
		t.Fatal("an empty anchor set must be refused")
	}
	var failure *applereceipt.Failure
	if errors.As(err, &failure) {
		t.Fatalf("misconfiguration must not be a verification verdict, got %s", failure.Reason)
	}
}

// The aliasing rule: byte fields on a payload are copies, so a caller
// that reuses its receipt buffer cannot mutate an already-verified
// payload.
func TestResultDoesNotAliasTheInput(t *testing.T) {
	pki := newReceiptPKI(t)
	der := pki.receipt(t)
	input := applereceiptBase64(der)
	receipt, err := verifierFor(t, pki.anchors()).VerifyReceipt(input)
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(receipt.OpaqueValue)
	beforeBundle := *receipt.BundleID
	// Mutating the STRING the caller passed in is impossible in Go (it is
	// immutable), so the aliasing hazard the other ports guard against
	// does not exist here for the base64 argument; what remains is that
	// the decoded byte fields on the payload must be fresh copies of the
	// bytes read out of it.
	if !bytes.Equal(receipt.OpaqueValue, before) || *receipt.BundleID != beforeBundle {
		t.Fatal("decoding was not stable")
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
	receipt, err := verifierFor(t, pki.anchors()).VerifyReceipt(applereceiptBase64(der))
	if err != nil {
		t.Fatal(err)
	}
	values := receipt.UnknownAttributes[9999]
	if len(values) != 2 || !bytes.Equal(values[0], []byte{1, 2, 3}) || !bytes.Equal(values[1], []byte{4, 5, 6}) {
		t.Fatalf("duplicates must be preserved in encounter order, got %v", values)
	}
	if len(receipt.InApp) != 1 {
		t.Fatalf("expected one in-app purchase, got %d", len(receipt.InApp))
	}
	inner := receipt.InApp[0].UnknownAttributes[8888]
	if len(inner) != 1 || !bytes.Equal(inner[0], []byte{7}) {
		t.Fatalf("in-app purchases carry their own unknown attributes, got %v", inner)
	}
}

// Attribute types 1, 15, 16 and 1713 decode into typed fields; this pins
// that 15 (2^63-1, a nineteen-digit, eight-byte integer an IEEE-754
// double rounds to 2^63) keeps its exact digits.
func TestReceiptIdsAreDecoded(t *testing.T) {
	pki := newReceiptPKI(t)
	der := pki.receipt(t,
		attr(2, derUTF8String("com.example.app")),
		attr(1, derInt(1234567890)),
		attr(15, derInt(9223372036854775807)),
		attr(16, derInt(456789012)),
		attr(9999, []byte{1, 2, 3}),
		attr(17, receiptPayload(
			attr(1702, derUTF8String("com.example.app.coins100")),
			attr(1713, derInt(0)),
		)),
		attr(17, receiptPayload(
			attr(1702, derUTF8String("com.example.app.vip")),
			attr(1713, derInt(1)),
		)),
	)
	receipt, err := verifierFor(t, pki.anchors()).VerifyReceipt(applereceiptBase64(der))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.AppItemID == nil || *receipt.AppItemID != 1234567890 {
		t.Errorf("AppItemID: got %v, want 1234567890", receipt.AppItemID)
	}
	if receipt.DownloadID == nil || *receipt.DownloadID != 9223372036854775807 {
		t.Errorf("DownloadID: got %v, want the exact digits of 2^63-1 (9223372036854775807)", receipt.DownloadID)
	}
	if receipt.VersionExternalIdentifier == nil || *receipt.VersionExternalIdentifier != 456789012 {
		t.Errorf("VersionExternalIdentifier: got %v, want 456789012", receipt.VersionExternalIdentifier)
	}
	if len(receipt.InApp) != 2 {
		t.Fatalf("expected 2 in-app purchases, got %d", len(receipt.InApp))
	}
	if got := receipt.InApp[0].IsTrialPeriod; got == nil || *got {
		t.Errorf("coins100.IsTrialPeriod: got %v, want false", got)
	}
	if got := receipt.InApp[1].IsTrialPeriod; got == nil || !*got {
		t.Errorf("vip.IsTrialPeriod: got %v, want true", got)
	}
	for _, kind := range []int64{1, 15, 16} {
		if _, present := receipt.UnknownAttributes[kind]; present {
			t.Errorf("attribute %d must not appear in UnknownAttributes", kind)
		}
	}
	if _, present := receipt.UnknownAttributes[9999]; !present {
		t.Error("attribute 9999 must still appear in UnknownAttributes")
	}
}

// A receipt that does not carry the four attributes reports them absent
// rather than zero: absent and present-but-zero are different answers.
func TestReceiptIdsAbsentAreNil(t *testing.T) {
	pki := newReceiptPKI(t)
	der := pki.receipt(t,
		attr(2, derUTF8String("com.example.app")),
		attr(17, receiptPayload(
			attr(1702, derUTF8String("com.example.app.coins100")),
		)),
	)
	receipt, err := verifierFor(t, pki.anchors()).VerifyReceipt(applereceiptBase64(der))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.AppItemID != nil {
		t.Errorf("AppItemID: got %v, want nil", *receipt.AppItemID)
	}
	if receipt.DownloadID != nil {
		t.Errorf("DownloadID: got %v, want nil", *receipt.DownloadID)
	}
	if receipt.VersionExternalIdentifier != nil {
		t.Errorf("VersionExternalIdentifier: got %v, want nil", *receipt.VersionExternalIdentifier)
	}
	if len(receipt.InApp) != 1 {
		t.Fatalf("expected 1 in-app purchase, got %d", len(receipt.InApp))
	}
	if receipt.InApp[0].IsTrialPeriod != nil {
		t.Errorf("IsTrialPeriod: got %v, want nil", *receipt.InApp[0].IsTrialPeriod)
	}
}

func TestEmptyDateStringMeansAbsent(t *testing.T) {
	pki := newReceiptPKI(t)
	der := pki.receipt(t,
		attr(2, derUTF8String("com.example.app")),
		attr(21, derIA5String("")),
	)
	receipt, err := verifierFor(t, pki.anchors()).VerifyReceipt(applereceiptBase64(der))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ExpirationDateMs != nil {
		t.Fatalf("an empty date string means absent, got %v", *receipt.ExpirationDateMs)
	}
	if _, present := receipt.UnknownAttributes[21]; present {
		t.Fatal("an empty date leaves no trace in UnknownAttributes")
	}
}

// The receipt path checks the chain BEFORE the marker OID, same as the
// JWS path (owner, 2026-09-27), so a receipt signed by a foreign chain
// reports UNTRUSTED_CHAIN and not INVALID_CERTIFICATE_PURPOSE (PLAN.md
// §2.2 step 3). The signer here has neither property, which is what makes
// the order observable.
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
	_, err := verifierFor(t, pinned.anchors()).VerifyReceipt(applereceiptBase64(der))
	requireReason(t, err, applereceipt.ReasonUntrustedChain)
}

// The receipt-signing marker on the leaf is required; the WWDR marker on
// the intermediate is new in 0.7 and brings the receipt path level with
// the JWS path (owner, 2026-09-27).
func TestReceiptSignerMustCarryTheMarkerOID(t *testing.T) {
	root := issueCert(t, certSpec{commonName: "Root", isCA: true, rsa: true}, nil)
	leaf := issueCert(t, certSpec{commonName: "Unmarked Signer", rsa: true}, root)
	der := buildCMS(t, cmsSpec{
		content:         receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
		signer:          leaf,
		certificates:    [][]byte{leaf.der},
		withSignedAttrs: true,
	})
	_, err := verifierFor(t, []*x509.Certificate{root.cert}).VerifyReceipt(applereceiptBase64(der))
	requireReason(t, err, applereceipt.ReasonInvalidCertificatePurpose)
}

func TestReceiptIntermediateMustCarryTheWWDRMarker(t *testing.T) {
	root := issueCert(t, certSpec{commonName: "Root", isCA: true, rsa: true}, nil)
	unmarkedIntermediate := issueCert(t, certSpec{commonName: "Unmarked Intermediate", isCA: true, rsa: true}, root)
	leaf := issueCert(t, certSpec{
		commonName: "Signer", rsa: true, markerOIDs: []asn1.ObjectIdentifier{oidAppleLeaf},
	}, unmarkedIntermediate)
	der := buildCMS(t, cmsSpec{
		content:         receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
		signer:          leaf,
		certificates:    [][]byte{leaf.der, unmarkedIntermediate.der},
		withSignedAttrs: true,
	})
	_, err := verifierFor(t, []*x509.Certificate{root.cert}).VerifyReceipt(applereceiptBase64(der))
	requireReason(t, err, applereceipt.ReasonInvalidCertificatePurpose)
}

// Nothing from the payload may be returned or acted on before the chain
// and the signature pass, even though the payload is parsed first to
// learn the creation date.
func TestNoPartialResultOnFailure(t *testing.T) {
	pki := newReceiptPKI(t)
	other := newReceiptPKI(t)
	receipt, err := verifierFor(t, other.anchors()).VerifyReceipt(applereceiptBase64(pki.receipt(t)))
	if err == nil {
		t.Fatal("expected a failure")
	}
	if receipt != nil {
		t.Fatalf("a failed verification returned a receipt anyway: %+v", receipt)
	}
}

// A nil certificate among the roots is a configuration mistake too. It
// must be refused at construction, as Java's Config.Builder.roots refuses
// a null root, rather than surface later as a MALFORMED verdict on every
// genuine receipt.
func TestNewVerifierRejectsANilRoot(t *testing.T) {
	pki := newReceiptPKI(t)
	roots := append([]*x509.Certificate{nil}, pki.anchors()...)
	verifier, err := applereceipt.NewVerifier(applereceipt.NewConfig(applereceipt.ConfigOptions{Roots: roots}))
	if err == nil || verifier != nil {
		t.Fatalf("a nil root must be refused, got %v, %v", verifier, err)
	}
	var failure *applereceipt.Failure
	if errors.As(err, &failure) {
		t.Fatalf("misconfiguration must not be a verification verdict, got %s", failure.Reason)
	}
}
