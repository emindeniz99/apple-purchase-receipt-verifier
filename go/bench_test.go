package applereceipt_test

import (
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

func benchReceiptVerifier(tb testing.TB, bundleID string) *applereceipt.ReceiptVerifier {
	tb.Helper()
	verifier, err := applereceipt.NewReceiptVerifier(applereceipt.ReceiptVerifierOptions{
		TrustedRoots: applereceipt.AppleReceiptRoots(), BundleID: bundleID,
	})
	if err != nil {
		tb.Fatal(err)
	}
	return verifier
}

func BenchmarkVerifyTransaction(b *testing.B) {
	root := parseFixtureCertificate(b, "jws-root")
	input := string(fixtureBytes(b, "transaction"))
	verifier, err := applereceipt.NewJWSVerifier(applereceipt.JWSVerifierOptions{
		TrustedRoots:         []*x509.Certificate{root},
		BundleID:             "com.example.app",
		AcceptedEnvironments: []applereceipt.Environment{applereceipt.EnvironmentSandbox},
	})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := verifier.VerifyTransaction(input); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyReceiptG5(b *testing.B) {
	verifier := benchReceiptVerifier(b, "dev.bonzer.weeka.app")
	input := fixtureBytes(b, "public-receipt-sandbox-g5")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := verifier.Verify(input); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyReceiptLegacy(b *testing.B) {
	verifier := benchReceiptVerifier(b, "com.nutcall.alert")
	input := fixtureBytes(b, "public-receipt-sandbox-legacy")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := verifier.Verify(input); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRejectCertificateFlood(b *testing.B) {
	input := certificateFlood(b)
	roots := applereceipt.AppleReceiptRoots()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := applereceipt.VerifyReceiptCore(input, roots); err == nil {
			b.Fatal("the flood must be rejected")
		}
	}
}

func BenchmarkVerifyReceiptEndpoint(b *testing.B) {
	root := parseFixtureCertificate(b, "receipt-root")
	body := []byte(`{"receipt-data":"` +
		base64.StdEncoding.EncodeToString(fixtureBytes(b, "receipt")) + `"}`)
	endpoint, err := applereceipt.NewVerifyReceiptEndpoint(applereceipt.VerifyReceiptEndpointOptions{
		TrustedRoots: []*x509.Certificate{root}, Environment: applereceipt.EnvironmentSandbox,
	})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		endpoint.VerifyReceiptJSON(body)
	}
}

// certificateFlood is a receipt padded with far more embedded
// certificates than a chain can hold. Rejecting it is the DoS-relevant
// path: without the pre-decode bound every one of them would be parsed
// and then RSA-checked as a candidate issuer.
func certificateFlood(tb testing.TB) []byte {
	tb.Helper()
	// Synthetic rather than an edited genuine receipt: the point is the
	// count, not the contents. Sized to stay comfortably under
	// DefaultMaxReceiptBytes, so it is the certificate bound being
	// exercised and not the input-size bound.
	filler := derSequence(derOctetString(make([]byte, 256)))
	certificates := make([][]byte, 0, 1024)
	for i := 0; i < 1024; i++ {
		certificates = append(certificates, filler)
	}
	return buildCMSFlood(tb, certificates)
}

func buildCMSFlood(tb testing.TB, certificates [][]byte) []byte {
	tb.Helper()
	// A minimal, structurally valid SignedData whose only unusual feature
	// is the certificate count.
	var flat []byte
	for _, cert := range certificates {
		flat = append(flat, cert...)
	}
	signedData := derSequence(
		derInt(1),
		derSet(algorithmIdentifier(oidSHA256)),
		derSequence(derOID(oidPKCS7Data),
			derContext0(derOctetString(receiptPayload(attr(2, derUTF8String("com.example.app")))))),
		derContext0(flat),
		derSet(derSequence(
			derInt(1),
			derSequence(derSequence(), derInt(1)),
			algorithmIdentifier(oidSHA256),
			algorithmIdentifier(oidRSA),
			derOctetString([]byte{1, 2, 3, 4}),
		)),
	)
	return derSequence(derOID(oidPKCS7Sign), derContext0(signedData))
}

// Rejecting a hostile blob must not cost dramatically more than accepting
// a genuine one. Node measured 26-45x for a 1057-certificate receipt
// before its bound went in; with the bound enforced before any
// certificate is decoded, rejection should be far cheaper than
// verification, not more expensive.
//
// A certificate flood is only one shape of that attack, and the cheapest
// to defeat, because the bound is a count comparison. The other shape is
// ASN.1 nesting, which is paid in the parser BEFORE the count is looked
// at; TestNestedReceiptDoesNotAmplify covers it.
func TestRejectionCostIsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-sensitive")
	}
	flood := certificateFlood(t)
	roots := applereceipt.AppleReceiptRoots()
	genuine := fixtureBytes(t, "public-receipt-sandbox-legacy")
	verifier := benchReceiptVerifier(t, "com.nutcall.alert")

	// Warm up, so neither figure pays for a first-call cost.
	_, _ = applereceipt.VerifyReceiptCore(flood, roots)
	_, _ = verifier.Verify(genuine)

	const runs = 20
	start := time.Now()
	for i := 0; i < runs; i++ {
		if _, err := verifier.Verify(genuine); err != nil {
			t.Fatal(err)
		}
	}
	accept := time.Since(start)

	start = time.Now()
	for i := 0; i < runs; i++ {
		if _, err := applereceipt.VerifyReceiptCore(flood, roots); err == nil {
			t.Fatal("the flood must be rejected")
		}
	}
	reject := time.Since(start)

	t.Logf("accepting a genuine 79 KB receipt: %v for %d runs; rejecting a "+
		"1024-certificate flood: %v", accept, runs, reject)
	// A generous ceiling: the point is to catch a regression that starts
	// decoding every embedded certificate, which costs orders of
	// magnitude, not to pin a ratio.
	if len(flood) >= applereceipt.DefaultMaxReceiptBytes {
		t.Fatalf("the flood is %d bytes, at or above the %d-byte input bound: this test "+
			"would be measuring the size check rather than the certificate bound",
			len(flood), applereceipt.DefaultMaxReceiptBytes)
	}
	if reject > 5*accept {
		t.Fatalf("rejecting the flood cost %v against %v to accept a genuine receipt; "+
			"the certificate bound is no longer being enforced before decoding", reject, accept)
	}
}

// An allocation ceiling on the happy paths. A regression that starts
// copying the payload per attribute, or re-parsing a certificate per hop,
// shows up here long before it shows up in a latency graph.
func TestAllocationsOnTheHappyPathsAreBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("allocation-sensitive")
	}
	t.Run("VerifyTransaction", func(t *testing.T) {
		root := parseFixtureCertificate(t, "jws-root")
		input := string(fixtureBytes(t, "transaction"))
		verifier, err := applereceipt.NewJWSVerifier(applereceipt.JWSVerifierOptions{
			TrustedRoots:         []*x509.Certificate{root},
			BundleID:             "com.example.app",
			AcceptedEnvironments: []applereceipt.Environment{applereceipt.EnvironmentSandbox},
		})
		if err != nil {
			t.Fatal(err)
		}
		allocations := testing.AllocsPerRun(20, func() {
			if _, err := verifier.VerifyTransaction(input); err != nil {
				t.Fatal(err)
			}
		})
		t.Logf("%.0f allocations per VerifyTransaction", allocations)
		if allocations > 500 {
			t.Fatalf("%.0f allocations per VerifyTransaction is a regression", allocations)
		}
	})
	t.Run("Verify (79 KB legacy receipt, 187 in-app purchases)", func(t *testing.T) {
		verifier := benchReceiptVerifier(t, "com.nutcall.alert")
		input := fixtureBytes(t, "public-receipt-sandbox-legacy")
		allocations := testing.AllocsPerRun(10, func() {
			if _, err := verifier.Verify(input); err != nil {
				t.Fatal(err)
			}
		})
		t.Logf("%.0f allocations per legacy receipt verification", allocations)
		if allocations > 60000 {
			t.Fatalf("%.0f allocations for one legacy receipt is a regression", allocations)
		}
	})
}
