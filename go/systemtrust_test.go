package applereceipt_test

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// The strongest form of "this library never reads the operating system
// trust store": put a certificate authority INTO the trust store, prove
// with crypto/x509 that the OS now trusts a chain under it, and then show
// that this library still rejects that chain.
//
// The CA is generated here rather than borrowed from a real public CA
// because a real one cannot be made to sign a test leaf. What matters is
// that it is genuinely a system root for this process — which the child
// asserts by having the platform verifier itself accept the chain before
// asking this library about it.
//
// It runs in a child process because Go caches the system pool behind a
// sync.Once, so SSL_CERT_FILE has to be in place before the first lookup.
func TestSystemTrustStoreIsNeverConsulted(t *testing.T) {
	if !inSubprocess() {
		output, err := runSelf(t, "TestSystemTrustStoreIsNeverConsulted")
		requireChildPassed(t, output, err)
		return
	}

	// --- child ---------------------------------------------------------
	root := issueCert(t, certSpec{commonName: "Definitely Trusted Root CA", isCA: true}, nil)
	intermediate := issueCert(t, certSpec{
		commonName: "Definitely Trusted Intermediate", isCA: true,
		markerOIDs: []asn1.ObjectIdentifier{oidAppleWWDR},
	}, root)
	leaf := issueCert(t, certSpec{
		commonName: "leaf.example", markerOIDs: []asn1.ObjectIdentifier{oidAppleLeaf},
	}, intermediate)

	bundle := filepath.Join(t.TempDir(), "system-roots.pem")
	if err := os.WriteFile(bundle, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: root.der}), 0o600); err != nil {
		t.Fatal(err)
	}
	// Read lazily by crypto/x509 on the first system-pool lookup, which
	// has not happened yet in this process.
	t.Setenv("SSL_CERT_FILE", bundle)
	t.Setenv("SSL_CERT_DIR", filepath.Dir(bundle))

	if _, err := x509.SystemCertPool(); err != nil {
		t.Skipf("this platform has no readable system trust store: %v", err)
	}

	// Premise 1: the operating system now trusts this chain. Verify with
	// a nil Roots is the platform verifier, so this is the OS's own
	// answer and not a re-implementation of it.
	//
	// Only Unix builds the pool from files, so SSL_CERT_FILE is the whole
	// mechanism for planting a root here. On darwin and windows crypto/x509
	// hands the chain to the platform verifier, which reads the keychain or
	// the certificate store and ignores the variable, and this process
	// cannot write to either without administrative rights. So the premise
	// is asserted where it can be, and the assertion that actually matters
	// — the library refusing the chain — still runs on all three.
	systemRootPlantable := runtime.GOOS != "darwin" && runtime.GOOS != "windows"
	if systemRootPlantable {
		intermediates := x509.NewCertPool()
		intermediates.AddCert(intermediate.cert)
		if _, err := leaf.cert.Verify(x509.VerifyOptions{
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			t.Fatalf("the premise failed: the platform verifier does not trust the chain "+
				"even with the root installed, so this test proves nothing: %v", err)
		}
	} else {
		t.Logf("%s verifies through the platform trust store, which SSL_CERT_FILE "+
			"does not reach, so the root could not be planted; the rejection below "+
			"is still asserted", runtime.GOOS)
	}

	// Premise 2: and the library still refuses it, with its production
	// anchors and with an unrelated set.
	jws := signJWS(t, leaf, [][]byte{leaf.der, intermediate.der, root.der}, transactionClaims())
	for _, anchors := range []struct {
		name  string
		roots []*x509.Certificate
	}{
		{"the bundled Apple roots", applereceipt.AppleJWSRoots()},
		{"an unrelated generated root", newJWSPKI(t).anchorSlice()},
	} {
		verifier, err := applereceipt.NewJWSVerifier(applereceipt.JWSVerifierOptions{
			TrustedRoots:         anchors.roots,
			BundleID:             "com.example.app",
			AcceptedEnvironments: []applereceipt.Environment{applereceipt.EnvironmentSandbox},
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = verifier.VerifyTransaction(jws)
		requireReason(t, err, applereceipt.ReasonInvalidChain)
	}

	// And the receipt path, which is the one with a path builder.
	receiptRoot := issueCert(t, certSpec{commonName: "Trusted Receipt Root", isCA: true, rsa: true}, nil)
	receiptLeaf := issueCert(t, certSpec{
		commonName: "Trusted Receipt Signer", rsa: true,
		markerOIDs: []asn1.ObjectIdentifier{oidAppleLeaf},
	}, receiptRoot)
	if err := os.WriteFile(bundle, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: receiptRoot.der}), 0o600); err != nil {
		t.Fatal(err)
	}
	der := buildCMS(t, cmsSpec{
		content:         receiptPayload(attr(2, derUTF8String("com.example.app"))),
		signer:          receiptLeaf,
		certificates:    [][]byte{receiptLeaf.der},
		withSignedAttrs: true,
	})
	_, receiptErr := applereceipt.VerifyReceiptCore(der, applereceipt.AppleReceiptRoots())
	requireReason(t, receiptErr, applereceipt.ReasonInvalidChain)
}
