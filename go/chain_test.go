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
// genuine Apple chain must fail against a synthesized root.
func TestAnchorsArePinnedInBothDirections(t *testing.T) {
	t.Run("synthesized chain against the real Apple roots", func(t *testing.T) {
		pki := newJWSPKI(t)
		verifier := jwsVerifierFor(t, applereceipt.AppleJWSRoots(), nil)
		_, err := verifier.VerifyTransaction(pki.sign(t, transactionClaims()))
		requireReason(t, err, applereceipt.ReasonInvalidChain)
	})
	t.Run("genuine Apple receipt against a synthesized root", func(t *testing.T) {
		pki := newReceiptPKI(t)
		_, err := applereceipt.VerifyReceiptCore(
			fixtureBytes(t, "public-receipt-sandbox-legacy"), pki.anchors())
		requireReason(t, err, applereceipt.ReasonInvalidChain)
	})
	t.Run("genuine Apple receipt against the real Apple roots", func(t *testing.T) {
		// The control: the same bytes and the right anchors do verify, so
		// the two rejections above are about trust and not about the
		// receipt being broken.
		receipt, err := applereceipt.VerifyReceiptCore(
			fixtureBytes(t, "public-receipt-sandbox-legacy"), applereceipt.AppleReceiptRoots())
		if err != nil {
			t.Fatalf("the genuine legacy receipt must verify against Apple's roots: %v", err)
		}
		if len(receipt.InAppPurchases) != 187 {
			t.Fatalf("expected 187 in-app purchases, got %d", len(receipt.InAppPurchases))
		}
	})
}

// Trust anchors are trusted by fiat: an anchor's own expiry is not
// checked. This is what lets a historical receipt verify under a root
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
	if _, err := jwsVerifierFor(t, []*x509.Certificate{root.cert}, nil).VerifyTransaction(jws); err != nil {
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
			_, err := jwsVerifierFor(t, []*x509.Certificate{root.cert}, nil).VerifyTransaction(jws)
			requireReason(t, err, applereceipt.ReasonInvalidChain)
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
	if _, err := jwsVerifierFor(t, []*x509.Certificate{root.cert}, nil).VerifyTransaction(good); err != nil {
		t.Fatalf("the correctly named intermediate must verify: %v", err)
	}
	// The twin holds the same key, so the leaf signature checks out under
	// it — and it must still be rejected on the name.
	swapped := signJWS(t, leaf, [][]byte{leaf.der, twin.der, root.der}, transactionClaims())
	_, err := jwsVerifierFor(t, []*x509.Certificate{root.cert}, nil).VerifyTransaction(swapped)
	requireReason(t, err, applereceipt.ReasonInvalidChain)
}

func TestSignatureAlgorithmAllowlist(t *testing.T) {
	t.Run("ECDSA-SHA384 is accepted", func(t *testing.T) {
		// Apple's own official JWS chains are SHA-384 signed; an
		// allowlist that forgot 384 would fail conformance.
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
		if _, err := jwsVerifierFor(t, []*x509.Certificate{root.cert}, nil).VerifyTransaction(jws); err != nil {
			t.Fatalf("ECDSA-SHA384 must be accepted: %v", err)
		}
	})
	t.Run("RSA-PSS is rejected", func(t *testing.T) {
		// A legitimate, strong algorithm that Apple does not use. It is
		// rejected by the allowlist rather than by the signature check,
		// which is the point: the set of accepted algorithms is closed.
		root := issueCert(t, certSpec{commonName: "PSS Root", isCA: true, rsa: true}, nil)
		intermediate := issueCert(t, certSpec{
			commonName: "PSS WWDR", isCA: true, rsa: true,
			markerOIDs: []asn1.ObjectIdentifier{oidAppleWWDR}, signatureAlgo: x509.SHA256WithRSAPSS,
		}, root)
		leaf := issueCert(t, certSpec{
			commonName: "PSS Leaf", markerOIDs: []asn1.ObjectIdentifier{oidAppleLeaf},
		}, intermediate)
		jws := signJWS(t, leaf, [][]byte{leaf.der, intermediate.der, root.der}, transactionClaims())
		_, err := jwsVerifierFor(t, []*x509.Certificate{root.cert}, nil).VerifyTransaction(jws)
		requireReason(t, err, applereceipt.ReasonInvalidChain)
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
		content:      receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
		signer:       selfSigned,
		certificates: [][]byte{selfSigned.der},
	})
	done := make(chan error, 1)
	go func() {
		_, err := applereceipt.VerifyReceiptCore(der, []*x509.Certificate{unrelated.cert})
		done <- err
	}()
	select {
	case err := <-done:
		requireReason(t, err, applereceipt.ReasonInvalidChain)
	case <-time.After(5 * time.Second):
		t.Fatal("the walk did not terminate on a self-issued certificate")
	}
}

// Ten certificates whose subject and issuer names all collide: every one
// of them looks like a plausible issuer for every other, so the walk has
// to be bounded by something other than luck.
func TestCrossSignedMeshRejectsInBoundedTime(t *testing.T) {
	anchor := issueCert(t, certSpec{commonName: "Unrelated Anchor", isCA: true, rsa: true}, nil)
	meshRoot := issueCert(t, certSpec{commonName: "Mesh", isCA: true, rsa: true}, nil)
	certificates := [][]byte{}
	var signer *testCert
	for i := 0; i < 10; i++ {
		cert := issueCert(t, certSpec{
			commonName: "Mesh", isCA: true, rsa: true,
			markerOIDs: []asn1.ObjectIdentifier{oidAppleLeaf},
		}, meshRoot)
		certificates = append(certificates, cert.der)
		if signer == nil {
			signer = cert
		}
	}
	der := buildCMS(t, cmsSpec{
		content:      receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
		signer:       signer,
		certificates: certificates,
	})

	start := time.Now()
	_, err := applereceipt.VerifyReceiptCore(der, []*x509.Certificate{anchor.cert})
	elapsed := time.Since(start)
	requireReason(t, err, applereceipt.ReasonInvalidChain)
	if elapsed > time.Second {
		t.Fatalf("rejecting a name-colliding mesh took %v; the visited set is not bounding the walk", elapsed)
	}
}

// A path longer than the bound is rejected rather than walked forever.
func TestPathLongerThanTheBoundIsRejected(t *testing.T) {
	root := issueCert(t, certSpec{commonName: "Deep Root", isCA: true, rsa: true}, nil)
	chain := [][]byte{}
	current := root
	for i := 0; i < 9; i++ {
		current = issueCert(t, certSpec{
			commonName: "Deep CA " + itoaTest(i), isCA: true, rsa: true,
		}, current)
		chain = append(chain, current.der)
	}
	leaf := issueCert(t, certSpec{
		commonName: "Deep Leaf", rsa: true, markerOIDs: []asn1.ObjectIdentifier{oidAppleLeaf},
	}, current)
	// Nine intermediates plus the leaf is exactly the ten-certificate
	// bound, so the walk — not the certificate count — is what rejects.
	certificates := append([][]byte{leaf.der}, chain...)
	der := buildCMS(t, cmsSpec{
		content:      receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
		signer:       leaf,
		certificates: certificates,
	})
	_, err := applereceipt.VerifyReceiptCore(der, []*x509.Certificate{root.cert})
	requireReason(t, err, applereceipt.ReasonInvalidChain)
}

func itoaTest(i int) string { return string(rune('a' + i)) }

// An intermediate that is not embedded cannot be conjured from anywhere:
// there is no AIA fetch and no other source of certificates.
func TestMissingIntermediateIsNotFetched(t *testing.T) {
	pki := newReceiptPKI(t)
	der := buildCMS(t, cmsSpec{
		content:      receiptPayload(standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())...),
		signer:       pki.leaf,
		certificates: [][]byte{pki.leaf.der}, // the intermediate is left out
	})
	_, err := applereceipt.VerifyReceiptCore(der, pki.anchors())
	requireReason(t, err, applereceipt.ReasonInvalidChain)
}
