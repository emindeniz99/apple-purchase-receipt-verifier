package applereceipt_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"testing"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// The keystone this port's legacy path rests on, asserted rather than
// assumed.
//
// Certificate.CheckSignatureFrom BANS SHA-1 certificate signatures, and
// the GODEBUG=x509sha1=1 escape hatch was removed in Go 1.24. The
// exported three-argument Certificate.CheckSignature still ALLOWS them.
// Every genuine legacy Apple receipt chain — leaf, WWDR intermediate and
// the Apple Inc. Root — is SHA1-RSA, so that asymmetry is the difference
// between verifying real receipts and rejecting all of them.
//
// It is public API but not a documented guarantee. If a future Go closes
// it, this test turns that into a red CI leg instead of into a production
// outage on the day someone upgrades their toolchain.
func TestSHA1CertificateSignaturesAreStillAcceptedByCheckSignature(t *testing.T) {
	// The genuine legacy chain, out of the public fixture, is the only
	// honest sample: a synthesized SHA-1 chain would prove less.
	receipt := fixtureBytes(t, "public-receipt-sandbox-legacy")
	if _, err := applereceipt.VerifyReceiptCore(receipt, applereceipt.AppleReceiptRoots()); err != nil {
		t.Fatalf("the genuine SHA-1 legacy receipt no longer verifies. If this is a "+
			"toolchain change rather than a code change, the documented fallback is to "+
			"replace Certificate.CheckSignature with rsa.VerifyPKCS1v15(pub, crypto.SHA1, "+
			"sha1(tbs), sig) in internal/chain: %v", err)
	}
}

// The same asymmetry, stated directly against crypto/x509 so the failure
// names the cause rather than a receipt.
func TestCheckSignatureAcceptsSHA1WhileCheckSignatureFromRejectsIt(t *testing.T) {
	root := issueCert(t, certSpec{
		commonName: "SHA-1 Root", isCA: true, rsa: true, signatureAlgo: x509.SHA1WithRSA,
	}, nil)
	leaf := issueCert(t, certSpec{
		commonName: "SHA-1 Leaf", rsa: true, signatureAlgo: x509.SHA1WithRSA,
	}, root)
	if leaf.cert.SignatureAlgorithm != x509.SHA1WithRSA {
		t.Fatalf("the toolchain would not issue a SHA-1 certificate; got %v",
			leaf.cert.SignatureAlgorithm)
	}

	if err := root.cert.CheckSignature(
		leaf.cert.SignatureAlgorithm, leaf.cert.RawTBSCertificate, leaf.cert.Signature); err != nil {
		t.Fatalf("Certificate.CheckSignature no longer accepts SHA1-RSA: %v\n"+
			"Every genuine legacy Apple receipt chain is SHA-1 signed. The fallback, "+
			"measured working and not removable, is rsa.VerifyPKCS1v15(pub, crypto.SHA1, "+
			"sha1(tbs), sig).", err)
	}
	if err := leaf.cert.CheckSignatureFrom(root.cert); err == nil {
		t.Log("note: CheckSignatureFrom now accepts SHA-1 too; the asymmetry this port " +
			"relies on has become moot, which is harmless")
	}

	// The documented fallback, exercised so it cannot rot: if
	// CheckSignature ever stops accepting SHA-1, this is the replacement.
	publicKey, ok := root.cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("the synthesized root is not RSA")
	}
	digest := sha1.Sum(leaf.cert.RawTBSCertificate)
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, digest[:], leaf.cert.Signature); err != nil {
		t.Fatalf("the documented fallback does not work either: %v", err)
	}
}
