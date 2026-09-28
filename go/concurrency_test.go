package applereceipt_test

import (
	"crypto/x509"
	"sync"
	"testing"
	"time"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// "Safe for concurrent use by multiple goroutines" is a claim on Verifier.
// Run under -race in CI, this is what makes it a tested claim rather than
// a doc comment, and it is the place a later cached buffer or memoised
// clock read would show up.
func TestVerifierIsSafeForConcurrentUse(t *testing.T) {
	receiptRoot := parseFixtureCertificate(t, "receipt-root")
	jwsRoot := parseFixtureCertificate(t, "jws-root")
	receiptBytes := fixtureBytes(t, "receipt")
	transaction := string(fixtureBytes(t, "transaction"))
	receiptBase64 := applereceiptBase64(receiptBytes)

	receipts := verifierFor(t, []*x509.Certificate{receiptRoot})
	jws := verifierFor(t, []*x509.Certificate{jwsRoot})
	at := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	endpoint := endpointVerifierFor(t, []*x509.Certificate{receiptRoot}, func() int64 { return at })

	// One reference answer per entry point; every goroutine must produce
	// exactly it.
	referenceReceipt, err := receipts.VerifyReceipt(receiptBase64)
	if err != nil {
		t.Fatal(err)
	}
	referencePayload, err := jws.VerifySignedData(transaction)
	if err != nil {
		t.Fatal(err)
	}
	wantReceipt := referenceReceipt.ToJSON()
	wantPayload := referencePayload.JSON()
	wantBody := endpoint.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, `{"receipt-data":"`+receiptBase64+`"}`)

	const goroutines = 64
	const iterations = 50
	var wg sync.WaitGroup
	errs := make(chan string, goroutines*3)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				receipt, err := receipts.VerifyReceipt(receiptBase64)
				if err != nil {
					errs <- "receipt: " + err.Error()
					return
				}
				if receipt.ToJSON() != wantReceipt {
					errs <- "receipt answer differs between goroutines"
					return
				}
				payload, err := jws.VerifySignedData(transaction)
				if err != nil {
					errs <- "transaction: " + err.Error()
					return
				}
				if payload.JSON() != wantPayload {
					errs <- "transaction answer differs between goroutines"
					return
				}
				body := endpoint.VerifyReceiptEndpoint(applereceipt.EnvironmentSandbox, `{"receipt-data":"`+receiptBase64+`"}`)
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

// The bundled root set is lazily initialised, so it gets its own race.
func TestAppleRootsIsSafeForConcurrentUse(t *testing.T) {
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if len(applereceipt.AppleRoots()) != 3 {
					t.Error("the bundled root set changed size under concurrency")
					return
				}
			}
		}()
	}
	wg.Wait()
}
