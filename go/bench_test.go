package applereceipt_test

import (
	"crypto/x509"
	"testing"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// One call at a time, and in parallel: the pool gives each goroutine its
// own instance, so parallel throughput is what a server sees.
//
//	go test -run '^$' -bench . -benchtime 3s

func benchVerifier(tb testing.TB, roots []*x509.Certificate) *applereceipt.Verifier {
	tb.Helper()
	return verifierFor(tb, roots)
}

func BenchmarkNewVerifier(b *testing.B) {
	benchVerifier(b, nil) // the first Verifier pays the module's compile
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := applereceipt.NewVerifier(applereceipt.DefaultConfig()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyReceiptG5(b *testing.B) {
	verifier := benchVerifier(b, nil)
	input := fixtureString(b, "public-receipt-sandbox-g5")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := verifier.VerifyReceipt(input); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyReceiptG5Parallel(b *testing.B) {
	verifier := benchVerifier(b, nil)
	input := fixtureString(b, "public-receipt-sandbox-g5")
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := verifier.VerifyReceipt(input); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func BenchmarkVerifySignedData(b *testing.B) {
	verifier := benchVerifier(b, []*x509.Certificate{parseFixtureCertificate(b, "jws-root")})
	input := string(fixtureBytes(b, "transaction"))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := verifier.VerifySignedData(input); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifySignedDataParallel(b *testing.B) {
	verifier := benchVerifier(b, []*x509.Certificate{parseFixtureCertificate(b, "jws-root")})
	input := string(fixtureBytes(b, "transaction"))
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := verifier.VerifySignedData(input); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func BenchmarkVerifyReceiptEndpoint(b *testing.B) {
	verifier := benchVerifier(b, nil)
	body := `{"receipt-data":"` + fixtureString(b, "public-receipt-sandbox-g5") + `"}`
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifier.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, body)
	}
}
