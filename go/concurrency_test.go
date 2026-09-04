package applereceipt_test

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"sync"
	"testing"
	"time"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// "Safe for concurrent use by multiple goroutines" is a claim on three
// public types. Run under -race in CI, this is what makes it a tested
// claim rather than a doc comment — and it is the place a later cached
// buffer or memoised *time.Location would show up.
func TestVerifiersAreSafeForConcurrentUse(t *testing.T) {
	receiptRoot := parseFixtureCertificate(t, "receipt-root")
	jwsRoot := parseFixtureCertificate(t, "jws-root")
	receiptBytes := fixtureBytes(t, "receipt")
	transaction := string(fixtureBytes(t, "transaction"))

	receipts, err := applereceipt.NewReceiptVerifier(applereceipt.ReceiptVerifierOptions{
		TrustedRoots: []*x509.Certificate{receiptRoot}, BundleID: "com.example.app",
	})
	if err != nil {
		t.Fatal(err)
	}
	jws, err := applereceipt.NewJWSVerifier(applereceipt.JWSVerifierOptions{
		TrustedRoots:         []*x509.Certificate{jwsRoot},
		BundleID:             "com.example.app",
		AcceptedEnvironments: []applereceipt.Environment{applereceipt.EnvironmentSandbox},
	})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	endpoint, err := applereceipt.NewVerifyReceiptEndpoint(applereceipt.VerifyReceiptEndpointOptions{
		TrustedRoots: []*x509.Certificate{receiptRoot},
		Environment:  applereceipt.EnvironmentSandbox,
		Now:          func() time.Time { return at },
	})
	if err != nil {
		t.Fatal(err)
	}

	// One reference answer per entry point; every goroutine must produce
	// exactly it.
	referenceReceipt, err := receipts.Verify(receiptBytes)
	if err != nil {
		t.Fatal(err)
	}
	referencePayload, err := jws.VerifyTransaction(transaction)
	if err != nil {
		t.Fatal(err)
	}
	wantReceipt := mustJSON(t, referenceReceipt)
	wantPayload := mustJSON(t, referencePayload)
	wantBody := string(endpoint.VerifyReceiptJSON([]byte(
		`{"receipt-data":"` + base64.StdEncoding.EncodeToString(receiptBytes) + `"}`)))

	const goroutines = 64
	const iterations = 50
	var wg sync.WaitGroup
	errs := make(chan string, goroutines*3)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				receipt, err := receipts.Verify(receiptBytes)
				if err != nil {
					errs <- "receipt: " + err.Error()
					return
				}
				if mustJSONNoT(receipt) != wantReceipt {
					errs <- "receipt answer differs between goroutines"
					return
				}
				payload, err := jws.VerifyTransaction(transaction)
				if err != nil {
					errs <- "transaction: " + err.Error()
					return
				}
				if mustJSONNoT(payload) != wantPayload {
					errs <- "transaction answer differs between goroutines"
					return
				}
				body := string(endpoint.VerifyReceiptJSON([]byte(
					`{"receipt-data":"` + base64.StdEncoding.EncodeToString(receiptBytes) + `"}`)))
				if body != wantBody {
					errs <- "endpoint answer differs between goroutines"
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for message := range errs {
		t.Error(message)
	}
}

// The bundled-root accessors are lazily initialised, so they get their
// own race.
func TestRootAccessorsAreSafeForConcurrentUse(t *testing.T) {
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if len(applereceipt.AppleJWSRoots()) != 3 || len(applereceipt.AppleReceiptRoots()) != 3 {
					t.Error("the bundled root set changed size under concurrency")
					return
				}
			}
		}()
	}
	wg.Wait()
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func mustJSONNoT(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "marshal error: " + err.Error()
	}
	return string(encoded)
}
