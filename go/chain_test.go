package applereceipt_test

import (
	"crypto/x509"
	"encoding/asn1"
	"testing"
	"time"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// The pinning property, stated both ways round: a chain that is perfectly
// well formed under its own root must fail against Apple's roots, and the
// genuine Apple chain must fail against a synthesized root. The exhaustive
// walk semantics (top-down, DoS bounds, RSA cap) are covered at the
// internal/chain package level; this file exercises the same properties
// through the public Verifier, where the marker-OID and config wiring
// also participate.
func TestAnchorsArePinnedInBothDirections(t *testing.T) {
	t.Run("synthesized chain against the real Apple roots", func(t *testing.T) {
		pki := newJWSPKI(t)
		verifier := verifierFor(t, applereceipt.AppleRoots())
		_, err := verifier.VerifySignedData(pki.sign(t, transactionClaims()))
		requireReason(t, err, applereceipt.ReasonUntrustedChain)
	})
	t.Run("genuine Apple receipt against a synthesized root", func(t *testing.T) {
		pki := newReceiptPKI(t)
		_, err := verifierFor(t, pki.anchors()).VerifyReceipt(fixtureString(t, "public-receipt-sandbox-legacy"))
		requireReason(t, err, applereceipt.ReasonUntrustedChain)
	})
	t.Run("genuine Apple receipt against the real Apple roots", func(t *testing.T) {
		// The control: the same bytes and the right anchors do verify, so
		// the two rejections above are about trust and not about the
		// receipt being broken.
		receipt, err := verifierFor(t, applereceipt.AppleRoots()).VerifyReceipt(fixtureString(t, "public-receipt-sandbox-legacy"))
		if err != nil {
			t.Fatalf("the genuine legacy receipt must verify against Apple's roots: %v", err)
		}
		if len(receipt.InApp) == 0 {
			t.Fatal("expected at least one in-app purchase")
		}
	})
}

// Trust anchors are trusted by fiat: an anchor's own expiry is not
// checked. This is what lets a historical payload verify under a root
// that has since expired, and it is standard PKIX semantics.
func TestExpiredAnchorStillAnchors(t *testing.T) {
	past := time.Now().Add(-20 * 365 * 24 * time.Hour)
	root := issueCert(t, certSpec{
		commonName: "Long Expired Root", isCA: true,
		notBefore: past, notAfter: past.Add(48 * time.Hour),
	}, nil)
	// The certificates below the anchor are current; only the anchor is
	// expired.
	intermediate := issueCert(t, certSpec{
		commonName: "Current WWDR", isCA: true,
		markerOIDs: []asn1.ObjectIdentifier{oidAppleWWDR},
	}, root)
	leaf := issueCert(t, certSpec{
		commonName: "Current Leaf", markerOIDs: []asn1.ObjectIdentifier{oidAppleLeaf},
	}, intermediate)

	jws := signJWS(t, leaf, [][]byte{leaf.der, intermediate.der, root.der}, transactionClaims())
	if _, err := verifierFor(t, []*x509.Certificate{root.cert}).VerifySignedData(jws); err != nil {
		t.Fatalf("an anchor's own expiry is not checked: %v", err)
	}
}

func TestIntermediateMustBeAUsableCA(t *testing.T) {
	tests := []struct {
		name string
		spec certSpec
	}{
		{"not a CA", certSpec{commonName: "Not a CA", isCA: false}},
		{"no basicConstraints extension at all", certSpec{
			commonName: "No basic constraints", isCA: true, noBasicConstraints: true,
		}},
		{"keyUsage without certSign", certSpec{
			commonName: "No certSign", isCA: true,
			setKeyUsage: true, keyUsage: x509.KeyUsageDigitalSignature,
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			root := issueCert(t, certSpec{commonName: "Root", isCA: true}, nil)
			spec := test.spec
			spec.markerOIDs = []asn1.ObjectIdentifier{oidAppleWWDR}
			intermediate := issueCert(t, spec, root)
			leaf := issueCert(t, certSpec{
				commonName: "Leaf", markerOIDs: []asn1.ObjectIdentifier{oidAppleLeaf},
			}, intermediate)
			jws := signJWS(t, leaf, [][]byte{leaf.der, intermediate.der, root.der}, transactionClaims())
			_, err := verifierFor(t, []*x509.Certificate{root.cert}).VerifySignedData(jws)
			requireReason(t, err, applereceipt.ReasonUntrustedChain)
		})
	}
}

// Names chain by exact DER bytes, not by "the signature happens to
// verify". The two intermediates here share one key, so the leaf's
// signature verifies under either of them; only the one whose subject
// name matches the leaf's issuer name may be used.
func TestIssuerNameMustMatchByBytes(t *testing.T) {
	root := issueCert(t, certSpec{commonName: "Shared Root", isCA: true}, nil)
	sharedKey := newKey(t, false)
	issuing := issueCert(t, certSpec{
		commonName: "WWDR A", isCA: true, key: sharedKey,
		markerOIDs: []asn1.ObjectIdentifier{oidAppleWWDR},
	}, root)
	twin := issueCert(t, certSpec{
		commonName: "WWDR B", isCA: true, key: sharedKey,
		markerOIDs: []asn1.ObjectIdentifier{oidAppleWWDR},
	}, root)
	leaf := issueCert(t, certSpec{
		commonName: "Leaf", markerOIDs: []asn1.ObjectIdentifier{oidAppleLeaf},
	}, issuing)

	// The control: the correctly named intermediate verifies.
	good := signJWS(t, leaf, [][]byte{leaf.der, issuing.der, root.der}, transactionClaims())
	if _, err := verifierFor(t, []*x509.Certificate{root.cert}).VerifySignedData(good); err != nil {
		t.Fatalf("the correctly named intermediate must verify: %v", err)
	}
	// The twin holds the same key, so the leaf signature checks out under
	// it — and it must still be rejected on the name.
	swapped := signJWS(t, leaf, [][]byte{leaf.der, twin.der, root.der}, transactionClaims())
	_, err := verifierFor(t, []*x509.Certificate{root.cert}).VerifySignedData(swapped)
	requireReason(t, err, applereceipt.ReasonUntrustedChain)
}

// Q14 (owner, 2026-09-27): there is no certificate signature-algorithm
// allowlist any more. Whatever crypto/x509 verifies under a pinned chain
// is accepted, including an algorithm the old 0.6 allowlist refused.
func TestNoSignatureAlgorithmAllowlist(t *testing.T) {
	t.Run("ECDSA-SHA384 is accepted", func(t *testing.T) {
		root := issueCert(t, certSpec{commonName: "P384 Root", isCA: true}, nil)
		intermediate := issueCert(t, certSpec{
			commonName: "P384 WWDR", isCA: true,
			markerOIDs: []asn1.ObjectIdentifier{oidAppleWWDR}, signatureAlgo: x509.ECDSAWithSHA384,
		}, root)
		leaf := issueCert(t, certSpec{
			commonName: "P384 Leaf", markerOIDs: []asn1.ObjectIdentifier{oidAppleLeaf},
			signatureAlgo: x509.ECDSAWithSHA384,
		}, intermediate)
		jws := signJWS(t, leaf, [][]byte{leaf.der, intermediate.der, root.der}, transactionClaims())
		if _, err := verifierFor(t, []*x509.Certificate{root.cert}).VerifySignedData(jws); err != nil {
			t.Fatalf("ECDSA-SHA384 must be accepted: %v", err)
		}
	})
	t.Run("RSA-PSS is accepted, unlike 0.6's closed allowlist", func(t *testing.T) {
		root := issueCert(t, certSpec{commonName: "PSS Root", isCA: true, rsa: true}, nil)
		intermediate := issueCert(t, certSpec{
			commonName: "PSS WWDR", isCA: true, rsa: true,
			markerOIDs: []asn1.ObjectIdentifier{oidAppleWWDR}, signatureAlgo: x509.SHA256WithRSAPSS,
		}, root)
		leaf := issueCert(t, certSpec{
			commonName: "PSS Leaf", markerOIDs: []asn1.ObjectIdentifier{oidAppleLeaf},
		}, intermediate)
		jws := signJWS(t, leaf, [][]byte{leaf.der, intermediate.der, root.der}, transactionClaims())
		if _, err := verifierFor(t, []*x509.Certificate{root.cert}).VerifySignedData(jws); err != nil {
			t.Fatalf("RSA-PSS must be accepted now that the allowlist is gone: %v", err)
		}
	})
}

// A certificate that names itself as its own issuer must terminate the
// walk, not loop it.
func TestSelfIssuedCertificateTerminatesTheWalk(t *testing.T) {
	selfSigned := issueCert(t, certSpec{
		commonName: "I Am My Own Issuer", isCA: true, rsa: true,
		markerOIDs: []asn1.ObjectIdentifier{oidAppleLeaf},
	}, nil)
	unrelated := issueCert(t, certSpec{commonName: "Real Anchor", isCA: true, rsa: true}, nil)

	der := buildCMS(t, cmsSpec{
		content:         receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
		signer:          selfSigned,
		certificates:    [][]byte{selfSigned.der},
		withSignedAttrs: true,
	})
	done := make(chan error, 1)
	verifier := verifierFor(t, []*x509.Certificate{unrelated.cert})
	go func() {
		_, err := verifier.VerifyReceipt(applereceiptBase64(der))
		done <- err
	}()
	select {
	case err := <-done:
		requireReason(t, err, applereceipt.ReasonUntrustedChain)
	case <-time.After(5 * time.Second):
		t.Fatal("the walk did not terminate on a self-issued certificate")
	}
}

// An intermediate that is not embedded cannot be conjured from anywhere:
// there is no AIA fetch and no other source of certificates.
func TestMissingIntermediateIsNotFetched(t *testing.T) {
	pki := newReceiptPKI(t)
	der := buildCMS(t, cmsSpec{
		content:         receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
		signer:          pki.leaf,
		certificates:    [][]byte{pki.leaf.der}, // the intermediate is left out
		withSignedAttrs: true,
	})
	_, err := verifierFor(t, pki.anchors()).VerifyReceipt(applereceiptBase64(der))
	requireReason(t, err, applereceipt.ReasonUntrustedChain)
}
